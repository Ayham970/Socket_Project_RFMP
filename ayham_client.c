#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUFFER_SIZE 100000

/* TCP may send or receive only part of the requested bytes. */
int send_bytes(int socket_fd, unsigned char data[], int length) {
    int total = 0;
    while (total < length) {
        int sent = send(socket_fd, data + total, length - total, 0);
        if (sent <= 0) {
            return 0;
        }
        total = total + sent;
    }
    return 1;
}

int receive_bytes(int socket_fd, unsigned char data[], int length) {
    int total = 0;
    while (total < length) {
        int received = recv(socket_fd, data + total, length - total, 0);
        if (received <= 0) {
            return 0;
        }
        total = total + received;
    }
    return 1;
}

/* A packet has a four-byte length followed by its text. */
int send_packet(int socket_fd, char message[]) {
    unsigned char header[4];
    int length = strlen(message);
    int remaining = length;
    for (int i = 3; i >= 0; i = i - 1) {
        header[i] = remaining % 256;
        remaining = remaining / 256;
    }
    if (send_bytes(socket_fd, header, 4) == 0) {
        return 0;
    }
    return send_bytes(socket_fd, (unsigned char *)message, length);
}

int receive_packet(int socket_fd, char response[], int response_size) {
    unsigned char header[4];
    unsigned long length = 0;
    if (receive_bytes(socket_fd, header, 4) == 0) {
        return 0;
    }
    for (int i = 0; i < 4; i = i + 1) {
        length = length * 256 + header[i];
    }
    /* Leave room for the string terminator. */
    if (length < 4 || length >= (unsigned long)response_size) {
        return 0;
    }
    if (receive_bytes(socket_fd, (unsigned char *)response, (int)length) == 0) {
        return 0;
    }
    response[length] = '\0';
    return 1;
}

char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Every three bytes become four Base64 characters. */
void base64_encode(char input[], int length, char output[]) {
    int i = 0;
    int j = 0;
    while (i < length) {
        unsigned char b1 = input[i];
        unsigned char b2 = 0;
        unsigned char b3 = 0;
        if (i + 1 < length) {
            b2 = input[i + 1];
        }
        if (i + 2 < length) {
            b3 = input[i + 2];
        }
        output[j] = base64_chars[b1 >> 2];
        output[j + 1] = base64_chars[((b1 & 3) << 4) | (b2 >> 4)];
        output[j + 2] = base64_chars[((b2 & 15) << 2) | (b3 >> 6)];
        output[j + 3] = base64_chars[b3 & 63];
        if (i + 1 >= length) {
            output[j + 2] = '=';
        }
        if (i + 2 >= length) {
            output[j + 3] = '=';
        }
        i = i + 3;
        j = j + 4;
    }
    output[j] = '\0';
}

int base64_value(char c) {
    for (int i = 0; i < 64; i = i + 1) {
        if (base64_chars[i] == c) {
            return i;
        }
    }
    return 0;
}

/* Recover the original bytes; '=' marks missing bytes. */
int base64_decode(char input[], char output[]) {
    int length = strlen(input);
    int i = 0;
    int j = 0;
    while (i + 3 < length) {
        int v1 = base64_value(input[i]);
        int v2 = base64_value(input[i + 1]);
        int v3 = base64_value(input[i + 2]);
        int v4 = base64_value(input[i + 3]);
        output[j] = (v1 << 2) | (v2 >> 4);
        j = j + 1;
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
    return j;
}

/* Return 1 for EE and display its error code and description. */
int is_error(char response[], char message[]) {
    if (strncmp(response, "(EE,", 4) != 0) {
        return 0;
    }
    int length = strlen(response);
    if (length < 7 || response[5] != ',' || response[length - 1] != ')') {
        printf("Invalid error packet from the server.\n");
    }
    else if (response[4] < '1' || response[4] > '4') {
        printf("Invalid error code from the server.\n");
    }
    else {
        response[length - 1] = '\0';
        base64_decode(response + 6, message);
        printf("Server error %c: %s\n", response[4], message);
        response[length - 1] = ')';
    }
    return 1;
}

/* Check the success message after reading a file or sending End. */
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
    response[strlen(response) - 1] = '\0';
    base64_decode(response + 4, message);
    if (strcmp(message, expected) != 0) {
        printf("Unexpected %s message: %s\n", stage, message);
        return 0;
    }
    return 1;
}

int main() {
    int command_failed = 0;
    char server_ip[16], server_address[16];
    char response[BUFFER_SIZE], file_data[BUFFER_SIZE], message[BUFFER_SIZE];
    char filename[256], encoded_name[400], request[500];

    printf("Enter the server address: ");
    scanf("%15s", server_ip);
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        printf("Could not create the socket.\n");
        return 1;
    }

    /* Linux IPv4 layout: family, port, address, then unused bytes. */
    memset(server_address, 0, 16);
    unsigned short *family = (unsigned short *)server_address;
    unsigned short *port_number = (unsigned short *)(server_address + 2);
    *family = AF_INET;
    *port_number = htons(5050);
    if (inet_pton(AF_INET, server_ip, server_address + 4) != 1) {
        printf("Invalid server address.\n");
        close(socket_fd);
        return 1;
    }
    printf("Connecting to the server...\n");
    if (connect(socket_fd, (void *)server_address, 16) < 0) {
        printf("Could not connect to the server.\n");
        close(socket_fd);
        return 1;
    }
    printf("Connected to the server.\n");

    /* Setup phase: SS -> CC. */
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
    scanf("%255s", filename);
    base64_encode(filename, strlen(filename), encoded_name);
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
        command_failed = 1;
    }
    else if (strncmp(response, "(DP,", 4) == 0) {
        if (response[strlen(response) - 1] != ')') {
            printf("Invalid data packet from the server.\n");
            close(socket_fd);
            return 1;
        }
        response[strlen(response) - 1] = '\0';
        base64_decode(response + 4, file_data);
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

    /* Closing phase: End -> SC,BYE. */
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
    close(socket_fd);
    printf("Connection closed.\n");
    return command_failed;
}
