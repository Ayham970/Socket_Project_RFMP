# ayham_client.py
# RFMP Python Client (Remote File Management Protocol)
# Uses packets.py (packet framing + Base64) and crypto_utils.py (RSA, AES, Caesar).

import socket

from packets import send_packet, receive_packet, encode_field, decode_field
from crypto_utils import generate_session_key, generate_rsa_keypair, serialize_public_key
from crypto_utils import load_public_key, encrypt_session_key, encrypt_payload, decrypt_payload

PORT = 5050


def get_reply(expected_type):
    # Receive the server's reply and check it.
    # If the server sent (EE,code,description), show the error and return None.
    packet_type, fields = receive_packet(s)

    if packet_type == "EE":
        print("Server error " + fields[0] + ": " + decode_field(fields[1]).decode())
        return None

    if packet_type != expected_type:
        raise ValueError("Unexpected reply from server: " + packet_type)

    return fields


def get_message():
    # Receive (SC,message) and return the message text, or None on (EE,...)
    fields = get_reply("SC")
    if fields is None:
        return None
    return decode_field(fields[0]).decode()


# create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    host = input("Server IP [127.0.0.1]: ").strip()
    if host == "":
        host = "127.0.0.1"

    mode = input("Choose NONE, AES or CAESAR: ").strip().upper()
    while mode not in ("NONE", "AES", "CAESAR"):
        mode = input("Please enter NONE, AES or CAESAR: ").strip().upper()

    # Session key: NONE = empty, AES = 32 random bytes, CAESAR = shift 1-25
    key = generate_session_key(mode)
    print("[ENC] Session key (" + mode + "):", key.hex())
    
    # connect to the server
    s.connect((host, PORT))

    # ---------- SETUP PHASE ----------
    if mode == "NONE":
        # (SS,RFMP,v1.0,0) -> (CC)
        send_packet(s, "SS", ["RFMP", "v1.0", "0"])
        if get_reply("CC") is None:
            raise ValueError("Server refused the connection")

    else:
        username = input("Username: ").strip()

        # The client makes its own RSA key pair
        private_key, public_key = generate_rsa_keypair()

        # (SS,RFMP,v1.0,1) -> (CC,server_public_key)
        send_packet(s, "SS", ["RFMP", "v1.0", "1"])
        fields = get_reply("CC")
        if fields is None:
            raise ValueError("Server refused the secured connection")

        # Encrypt the session key with the server PUBLIC key
        server_public_key = load_public_key(decode_field(fields[0]))
        encrypted_key = encrypt_session_key(server_public_key, key)

        # (EC,algorithm,encrypted_session_key,username:client_public_key)
        credentials = encode_field(username.encode()) + ":" + encode_field(serialize_public_key(public_key))
        send_packet(s, "EC", [mode, encode_field(encrypted_key), credentials])

        if get_message() != "SETUP_COMPLETE":
            raise ValueError("Encryption setup failed")

    print("Connected to " + host + " using " + mode + " mode.")

    # ---------- OPERATION PHASE ----------
    while True:
        print("\n1. Run a command")
        print("2. Read a file (openRead)")
        print("3. Write a file (openWrite)")
        print("4. End")
        choice = input("Choose 1-4: ").strip()

        if choice == "1":
            # (CM,prompt,command) -> (SC,output) or (EE,...)
            print("Commands: mkdir, cd, rmdir, rd, del, ren, ls, pwd, whoami, hostname, date")
            command = input("Command: ")
            send_packet(s, "CM", ["prompt", encode_field(command.encode())])
            output = get_message()
            if output is not None:
                print(output)

        elif choice == "2":
            # (CM,openRead,filename) -> (DP,data) -> (SC,READ_COMPLETE)
            filename = input("Server filename: ")
            send_packet(s, "CM", ["openRead", encode_field(filename.encode())])

            fields = get_reply("DP")
            if fields is None:
                continue

            # Decrypt with the session key (NONE returns the same data)
            print("[ENC] Received (encrypted):", decode_field(fields[0]))
            data = decrypt_payload(decode_field(fields[0]), mode, key)
            print("[ENC] After decryption    :", data)
            get_message()  # READ_COMPLETE

            print("----- " + filename + " -----")
            print(data.decode())

            save_name = input("Save a copy as (press Enter to skip): ").strip()
            if save_name != "":
                file = open(save_name, "wb")
                file.write(data)
                file.close()
                print("Saved to " + save_name)

        elif choice == "3":
            # (CM,openWrite,filename) -> (SC,READY) -> (DP,text) -> (SC,SAVED)
            filename = input("File name on server: ")

            # The user types the text to save, one line at a time
            print("Type the text to save. Press Enter on an empty line to finish.")
            lines = []
            while True:
                line = input()
                if line == "":
                    break
                lines.append(line)
            data = ("\n".join(lines) + "\n").encode()

            send_packet(s, "CM", ["openWrite", encode_field(filename.encode())])
            if get_message() != "READY":
                continue

            # Encrypt with the session key before sending
            data = encrypt_payload(data, mode, key)
            send_packet(s, "DP", [encode_field(data)])

            if get_message() == "SAVED":
                print("File saved on the server.")

        elif choice == "4":
            # ---------- CLOSING PHASE ----------
            # (End) -> (SC,BYE)
            send_packet(s, "End", [])
            get_message()
            print("Goodbye.")
            break

        else:
            print("Please choose 1, 2, 3 or 4.")

except ConnectionRefusedError:
    print("Could not connect. Is the server running?")
except (EOFError, ConnectionError):
    print("Connection to the server was lost.")
except Exception as error:
    print("Error:", error)
finally:
    s.close()
