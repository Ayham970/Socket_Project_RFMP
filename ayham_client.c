/* RFMP C client: connect without encryption, read one file, then close. */
#include <stdio.h>       /* printf() and scanf() */
#include <string.h>      /* String comparisons, copying and length */
#include <unistd.h>      /* close() */
#include <arpa/inet.h>   /* inet_pton() and htons() */
#include <sys/socket.h> /* socket(), connect(), send() and recv() */

/* Array capacity in bytes. The encoded packet and '\0' must fit. */
#define BUFFER_SIZE 100000

/* TCP can send only part of the data in one call. Return 1 on success. */
int send_bytes(int socket_fd, unsigned char data[], int length) {
    int total = 0;
    while (total < length) {
        /* Skip bytes already sent; request only the bytes still remaining. */
        int sent = send(socket_fd, data + total, length - total, 0);
        if (sent <= 0) {
            /* Stop if sending fails or makes no progress. */
            return 0;
        }
        total = total + sent;
    }
    return 1;
}

/* Collect exactly length bytes, even if they arrive in smaller pieces. */
int receive_bytes(int socket_fd, unsigned char data[], int length) {
    int total = 0;
    while (total < length) {
        /* Store the next piece after the bytes already received. */
        int received = recv(socket_fd, data + total, length - total, 0);
        if (received <= 0) {
            /* recv() returns 0 on disconnection and -1 on an error. */
            return 0;
        }
        total = total + received;
    }
    return 1;
}

/* A packet has a four-byte length followed by its text. */
int send_packet(int socket_fd, char message[]) {
    /* unsigned char holds one byte, with values from 0 to 255. */
    unsigned char header[4];
    /* strlen() counts the text bytes without the ending '\0'. */
    int length = strlen(message);
    int remaining = length;
    /* Fill from right to left: the highest-value byte is sent first.
       For example, length 300 becomes the byte values 0, 0, 1, 44. */
    for (int i = 3; i >= 0; i = i - 1) {
        header[i] = remaining % 256;  /* Extract the lowest-value byte. */
        remaining = remaining / 256; /* Move to the next byte. */
    }
    if (send_bytes(socket_fd, header, 4) == 0) {
        return 0;
    }
    /* Send the text after its header. The cast changes the pointer type,
       not the contents. The string terminator is not sent. */
    return send_bytes(socket_fd, (unsigned char *)message, length);
}

/* Read one packet into response. Return 0 if receiving or size checks fail. */
int receive_packet(int socket_fd, char response[], int response_size) {
    unsigned char header[4];
    unsigned long length = 0;
    if (receive_bytes(socket_fd, header, 4) == 0) {
        return 0;
    }
    /* Rebuild the length from its four bytes: 1 * 256 + 44 = 300. */
    for (int i = 0; i < 4; i = i + 1) {
        length = length * 256 + header[i];
    }
    /* (CC) is the smallest valid body: four bytes.
       Reject packets that would leave no room for the string terminator. */
    if (length < 4 || length >= (unsigned long)response_size) {
        return 0;
    }
    if (receive_bytes(socket_fd, (unsigned char *)response, (int)length) == 0) {
        return 0;
    }
    /* Add a local terminator so printf() and string functions can use it. */
    response[length] = '\0';
    return 1;
}

/* Base64 is encoding, not encryption. Each index 0-63 represents six bits. */
char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Every three bytes become four Base64 characters. */
void base64_encode(char input[], int length, char output[]) {
    int i = 0; /* Position in the original bytes. */
    int j = 0; /* Position in the encoded text. */
    while (i < length) {
        /* Take up to three bytes. Missing bytes start as zero. */
        unsigned char b1 = input[i];
        unsigned char b2 = 0;
        unsigned char b3 = 0;
        if (i + 1 < length) {
            b2 = input[i + 1];
        }
        if (i + 2 < length) {
            b3 = input[i + 2];
        }
        /* >> and << move bits; & selects bits; | combines the pieces.
           Split these 24 bits into four six-bit alphabet indexes. */
        output[j] = base64_chars[b1 >> 2];
        output[j + 1] = base64_chars[((b1 & 3) << 4) | (b2 >> 4)];
        output[j + 2] = base64_chars[((b2 & 15) << 2) | (b3 >> 6)];
        output[j + 3] = base64_chars[b3 & 63];
        /* One input byte needs '=='; two input bytes need '='. */
        if (i + 1 >= length) {
            output[j + 2] = '=';
        }
        if (i + 2 >= length) {
            output[j + 3] = '=';
        }
        /* Move past the three input bytes and four output characters. */
        i = i + 3;
        j = j + 4;
    }
    output[j] = '\0';
}

/* Find the numeric value of one character in the Base64 alphabet. */
int base64_value(char c) {
    for (int i = 0; i < 64; i = i + 1) {
        if (base64_chars[i] == c) {
            return i;
        }
    }
    /* Padding '=' and unrecognized characters fall through to zero. */
    return 0;
}

/* Recover the original bytes; '=' marks missing bytes. */
int base64_decode(char input[], char output[]) {
    int length = strlen(input);
    int i = 0;
    int j = 0;
    while (i + 3 < length) {
        /* Process four encoded characters at a time. */
        int v1 = base64_value(input[i]);
        int v2 = base64_value(input[i + 1]);
        int v3 = base64_value(input[i + 2]);
        int v4 = base64_value(input[i + 3]);
        /* Join the bits back into the original first byte. */
        output[j] = (v1 << 2) | (v2 >> 4);
        j = j + 1;
        /* Padding tells us whether a second or third byte exists. */
        if (input[i + 2] != '=') {
            output[j] = ((v2 & 15) << 4) | (v3 >> 2);
            j = j + 1;
        }
        if (input[i + 3] != '=') {
            output[j] = ((v3 & 3) << 6) | v4;
            j = j + 1;
        }
        i = i + 4;
    }
    output[j] = '\0';
    return j; /* Number of decoded bytes, excluding the terminator. */
}

/* Return 1 if this is an EE reply, even when its fields are malformed.
   Return 0 for other packet types so the caller can check them next. */
int is_error(char response[], char message[]) {
    /* strncmp() compares the first four characters; 0 means they match. */
    if (strncmp(response, "(EE,", 4) != 0) {
        return 0;
    }
    int length = strlen(response);
    /* Format: (EE,code,description). Index 4 is the one-digit code,
       index 5 is a comma, and index 6 starts the encoded description. */
    if (length < 7 || response[5] != ',' || response[length - 1] != ')') {
        printf("Invalid error packet from the server.\n");
    }
    else if (response[4] < '1' || response[4] > '4') {
        printf("Invalid error code from the server.\n");
    }
    else {
        /* Hide the last ')' while decoding, then restore the original packet. */
        response[length - 1] = '\0';
        base64_decode(response + 6, message);
        printf("Server error %c: %s\n", response[4], message);
        response[length - 1] = ')';
    }
    return 1;
}

/* Check SC after the caller has checked EE. expected is READ_COMPLETE or BYE;
   stage is a label for our error messages, not a field sent over the network. */
int check_success(char response[], char expected[], char stage[], char message[]) {
    if (strncmp(response, "(SC,", 4) != 0) {
        printf("Unexpected %s response: %s\n", stage, response);
        return 0;
    }
    if (response[strlen(response) - 1] != ')') {
        if (strcmp(stage, "closing") == 0) {
            printf("Invalid closing packet from the server.\n");
        }
        else {
            printf("Invalid success packet from the server.\n");
        }
        return 0;
    }
    /* Skip '(SC,' and decode the message without its final ')'. */
    response[strlen(response) - 1] = '\0';
    base64_decode(response + 4, message);
    /* strcmp() returns 0 only when the complete strings match. */
    if (strcmp(message, expected) != 0) {
        printf("Unexpected %s message: %s\n", stage, message);
        return 0;
    }
    return 1;
}

int main() {
    /* Keep a failed read recorded even if the closing exchange succeeds. */
    int command_failed = 0;
    /* server_ip is typed text; server_address holds the binary address. */
    char server_ip[16], server_address[16];
    /* Raw packet, decoded file, and decoded success/error message. */
    char response[BUFFER_SIZE], file_data[BUFFER_SIZE], message[BUFFER_SIZE];
    char filename[256], encoded_name[400], request[500];

    printf("Enter the server address: ");
    /* Read at most 15 characters, leaving one array cell for '\0'. */
    scanf("%15s", server_ip);
    /* IPv4 + stream socket + default protocol gives us TCP.
       socket_fd is the connection identifier returned by the operating system. */
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        printf("Could not create the socket.\n");
        return 1;
    }

    /* Linux IPv4 layout: bytes 0-1 family, 2-3 port, 4-7 IPv4 address.
       The remaining bytes are zero. These offsets are Linux-specific. */
    memset(server_address, 0, 16);
    /* These pointers let us write two-byte values into the address array. */
    unsigned short *family = (unsigned short *)server_address;
    unsigned short *port_number = (unsigned short *)(server_address + 2);
    *family = AF_INET;
    *port_number = htons(5050); /* Put the port in network byte order. */
    /* Convert the typed address, such as 127.0.0.1, into four binary bytes. */
    if (inet_pton(AF_INET, server_ip, server_address + 4) != 1) {
        printf("Invalid server address.\n");
        close(socket_fd);
        return 1;
    }
    printf("Connecting to the server...\n");
    /* Pass the address array to connect() using a general pointer. */
    if (connect(socket_fd, (void *)server_address, 16) < 0) {
        printf("Could not connect to the server.\n");
        close(socket_fd);
        return 1;
    }
    printf("Connected to the server.\n");

    /* Setup phase: SS -> CC. The final 0 requests no encryption. */
    if (send_packet(socket_fd, "(SS,RFMP,v1.0,0)") == 0) {
        printf("Could not send the setup packet.\n");
        close(socket_fd);
        return 1;
    }
    printf("Sent: (SS,RFMP,v1.0,0)\n");
    if (receive_packet(socket_fd, response, BUFFER_SIZE) == 0) {
        printf("Could not receive the server response.\n");
        close(socket_fd);
        return 1;
    }
    printf("Received: %s\n", response);
    /* Handle an error before requiring the normal connection confirmation. */
    if (is_error(response, message) == 1) {
        close(socket_fd);
        return 1;
    }
    if (strcmp(response, "(CC)") != 0) {
        printf("The server did not accept the connection.\n");
        close(socket_fd);
        return 1;
    }
    printf("Handshake completed successfully.\n");

    /* Operation phase: openRead -> DP -> SC,READ_COMPLETE. */
    printf("Enter the file name to read from the server: ");
    /* This input accepts one filename without spaces, up to 255 characters. */
    scanf("%255s", filename);
    /* Base64 keeps the filename separate from the packet's commas.
       Example: test.txt becomes dGVzdC50eHQ=. */
    base64_encode(filename, strlen(filename), encoded_name);
    /* strcpy() starts the request; strcat() appends the remaining parts. */
    strcpy(request, "(CM,openRead,");
    strcat(request, encoded_name);
    strcat(request, ")");
    if (send_packet(socket_fd, request) == 0) {
        printf("Could not send the openRead packet.\n");
        close(socket_fd);
        return 1;
    }
    printf("Sent: %s\n", request);
    if (receive_packet(socket_fd, response, BUFFER_SIZE) == 0) {
        printf("Could not receive the file (it may be too large).\n");
        close(socket_fd);
        return 1;
    }
    if (is_error(response, message) == 1) {
        /* No DP follows this error. Continue to the closing phase. */
        command_failed = 1;
    }
    else if (strncmp(response, "(DP,", 4) == 0) {
        if (response[strlen(response) - 1] != ')') {
            printf("Invalid data packet from the server.\n");
            close(socket_fd);
            return 1;
        }
        /* Remove ')' and skip the four characters '(DP,' to reach the data. */
        response[strlen(response) - 1] = '\0';
        base64_decode(response + 4, file_data);
        /* DP is followed by another reply. It must also be checked for EE. */
        if (receive_packet(socket_fd, response, BUFFER_SIZE) == 0) {
            printf("Could not receive the read completion response.\n");
            close(socket_fd);
            return 1;
        }
        if (is_error(response, message) == 1) {
            command_failed = 1;
        }
        else if (check_success(response, "READ_COMPLETE", "read completion", message) == 0) {
            close(socket_fd);
            return 1;
        }
        else {
            /* Display the contents only after SC confirms READ_COMPLETE. */
            printf("----- %s -----\n", filename);
            printf("%s\n", file_data);
            printf("-----------------\n");
        }
    }
    else {
        printf("Unexpected reply: %s\n", response);
        close(socket_fd);
        return 1;
    }

    /* Closing phase: End -> SC,BYE. End is a control packet, not a file command. */
    if (send_packet(socket_fd, "(End)") == 0) {
        printf("Could not send the End packet.\n");
        close(socket_fd);
        return 1;
    }
    printf("Sent: (End)\n");
    if (receive_packet(socket_fd, response, BUFFER_SIZE) == 0) {
        printf("Could not receive the closing response.\n");
        close(socket_fd);
        return 1;
    }
    printf("Received: %s\n", response);
    if (is_error(response, message) == 1) {
        close(socket_fd);
        return 1;
    }
    if (check_success(response, "BYE", "closing", message) == 0) {
        close(socket_fd);
        return 1;
    }
    /* Release the connection after checking its final response. */
    close(socket_fd);
    printf("Connection closed.\n");
    /* main returns 0 for success, or 1 if the file request failed. */
    return command_failed;
}
