# ayham_server.py
# RFMP Server (Remote File Management Protocol)
# One thread per client. Each client has its own session.
# Uses packets.py (packet framing + Base64) and crypto_utils.py (RSA, AES, Caesar).

import socket
import threading
import os
import subprocess
import time

from packets import send_packet, receive_packet, encode_field, decode_field, ProtocolError
from crypto_utils import generate_rsa_keypair, serialize_public_key, load_public_key
from crypto_utils import decrypt_session_key, encrypt_payload, decrypt_payload

HOST = "0.0.0.0"
PORT = 5050

# Folder where the server keeps the clients' files
SERVER_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server_storage")

# Error codes
# 1 = protocol error (wrong packet)
# 2 = file or folder error
# 3 = command error
# 4 = encryption error


def send_error(clientsocket, code, description):
    # (EE,code,description)
    send_packet(clientsocket, "EE", [str(code), encode_field(description.encode())])


def send_success(clientsocket, message):
    # (SC,message)
    send_packet(clientsocket, "SC", [encode_field(message.encode())])


# ---------- PROMPT COMMANDS ----------
# Returns the output text. Raises ValueError for a bad command
# and OSError if the file/folder operation fails.
def run_command(session, words):
    name = words[0]
    args = words[1:]
    folder = session["current_directory"]

    if name == "mkdir" and len(args) == 1:
        os.mkdir(os.path.join(folder, args[0]))
        return "Folder created: " + args[0]

    elif name == "cd" and len(args) == 1:
        new_folder = os.path.abspath(os.path.join(folder, args[0]))
        if not os.path.isdir(new_folder):
            raise FileNotFoundError(2, "Folder not found")
        # Only THIS client's directory changes (no os.chdir, which
        # would change the directory for every thread)
        session["current_directory"] = new_folder
        return new_folder

    elif (name == "rmdir" or name == "rd") and len(args) == 1:
        os.rmdir(os.path.join(folder, args[0]))
        return "Folder removed: " + args[0]

    elif name == "del" and len(args) == 1:
        os.remove(os.path.join(folder, args[0]))
        return "File deleted: " + args[0]

    elif name == "ren" and len(args) == 2:
        os.rename(os.path.join(folder, args[0]), os.path.join(folder, args[1]))
        return "Renamed " + args[0] + " to " + args[1]

    elif name == "ls" and len(args) == 0:
        return "\n".join(os.listdir(folder))

    elif name == "pwd" and len(args) == 0:
        return folder

    elif name == "whoami" and len(args) == 0:
        result = subprocess.run(["whoami"], capture_output=True, text=True)
        return result.stdout.strip()

    elif name == "hostname" and len(args) == 0:
        result = subprocess.run(["hostname"], capture_output=True, text=True)
        return result.stdout.strip()

    elif name == "date" and len(args) == 0:
        return time.ctime()

    else:
        raise ValueError("Unknown command or wrong arguments: " + " ".join(words))


def handle_prompt(clientsocket, session, command_field):
    # (CM,prompt,command) -> (SC,output) or (EE,...)
    words = decode_field(command_field).decode().split()
    if len(words) == 0:
        send_error(clientsocket, 3, "Empty command")
        return

    try:
        output = run_command(session, words)
        send_success(clientsocket, output)
    except ValueError as e:
        send_error(clientsocket, 3, str(e))
    except OSError as e:
        # e.strerror is the reason, e.g. "No such file or directory"
        send_error(clientsocket, 2, e.strerror + ": " + " ".join(words[1:]))


# ---------- openRead ----------
def handle_open_read(clientsocket, session, filename_field):
    # (CM,openRead,filename) -> (DP,data) then (SC,READ_COMPLETE)
    filename = decode_field(filename_field).decode()
    path = os.path.join(session["current_directory"], filename)

    try:
        file = open(path, "rb")
        data = file.read()
        file.close()
    except OSError:
        send_error(clientsocket, 2, "File not found: " + filename)
        return

    # Encrypt with the session key (NONE mode returns the same data)
    data = encrypt_payload(data, session["mode"], session["session_key"])

    send_packet(clientsocket, "DP", [encode_field(data)])
    send_success(clientsocket, "READ_COMPLETE")

# ---------- openWrite ----------
def handle_open_write(clientsocket, session, filename_field):
    # (CM,openWrite,filename): create the new file in write mode
    filename = decode_field(filename_field).decode()
    path = os.path.join(session["current_directory"], filename)

    try:
        file = open(path, "wb")
    except OSError as e:
        send_error(clientsocket, 2, e.strerror + ": " + filename)
        return
    send_success(clientsocket, "READY")

    # (DP,data): the data to save in the file created above
    packet_type, fields = receive_packet(clientsocket)
    if packet_type != "DP":
        file.close()
        send_error(clientsocket, 1, "Expected DP packet")
        return

    # Decrypt with the session key before saving
    try:
        data = decrypt_payload(decode_field(fields[0]), session["mode"], session["session_key"])
    except Exception:
        file.close()
        send_error(clientsocket, 4, "Could not decrypt the file data")
        return

    file.write(data)
    file.close()
    send_success(clientsocket, "SAVED")



# ---------- SECURED SETUP ----------
def secured_setup(clientsocket, session):
    # After (SS,RFMP,v1.0,1). Returns True if setup worked.

    # 1. Make the server RSA keys and send the public key: (CC,server_public_key)
    private_key, public_key = generate_rsa_keypair()
    send_packet(clientsocket, "CC", [encode_field(serialize_public_key(public_key))])

    # 2. Receive (EC,algorithm,encrypted_session_key,username:client_public_key)
    packet_type, fields = receive_packet(clientsocket)
    if packet_type != "EC":
        send_error(clientsocket, 1, "Expected EC packet")
        return False

    algorithm = fields[0]
    if algorithm != "AES" and algorithm != "CAESAR":
        send_error(clientsocket, 4, "Unsupported algorithm: " + algorithm)
        return False

    username_field, client_key_field = fields[2].split(":")

    # 3. Decrypt the session key with the server PRIVATE key
    try:
        session_key = decrypt_session_key(private_key, decode_field(fields[1]))
        client_public_key = load_public_key(decode_field(client_key_field))
    except Exception:
        send_error(clientsocket, 4, "Could not read the session key")
        return False

    # 4. Save everything in this client's session
    session["mode"] = algorithm
    session["session_key"] = session_key
    session["username"] = decode_field(username_field).decode()
    session["client_public_key"] = client_public_key

    send_success(clientsocket, "SETUP_COMPLETE")
    return True


# ---------- ONE CLIENT ----------
def handle_client(clientsocket, addr):
    print("Got a connection from %s" % str(addr))

    # Separate session for this client only
    session = {
        "current_directory": SERVER_ROOT,
        "mode": "NONE",
        "session_key": b"",
        "username": None,
        "client_public_key": None,
    }

    try:
        # ---------- SETUP PHASE ----------
        # (SS,RFMP,v1.0,0) or (SS,RFMP,v1.0,1)
        packet_type, fields = receive_packet(clientsocket)

        if packet_type != "SS" or fields[0] != "RFMP" or fields[1] != "v1.0":
            send_error(clientsocket, 1, "Expected (SS,RFMP,v1.0,0 or 1)")
            return

        if fields[2] == "0":
            send_packet(clientsocket, "CC", [])
        elif fields[2] == "1":
            if not secured_setup(clientsocket, session):
                return
        else:
            send_error(clientsocket, 1, "Security flag must be 0 or 1")
            return

        print("Setup done with %s, mode %s" % (str(addr), session["mode"]))

        # ---------- OPERATION PHASE ----------
        while True:
            packet_type, fields = receive_packet(clientsocket)

            # ---------- CLOSING PHASE ----------
            if packet_type == "End":
                send_success(clientsocket, "BYE")
                break

            elif packet_type == "CM" and fields[0] == "prompt":
                handle_prompt(clientsocket, session, fields[1])

            elif packet_type == "CM" and fields[0] == "openRead":
                handle_open_read(clientsocket, session, fields[1])

            elif packet_type == "CM" and fields[0] == "openWrite":
                handle_open_write(clientsocket, session, fields[1])

            else:
                send_error(clientsocket, 1, "Unexpected packet: " + packet_type)

    except ProtocolError as e:
        # Badly formed packet
        send_error(clientsocket, 1, str(e))

    except (EOFError, OSError):
        print("Client disconnected: %s" % str(addr))

    finally:
        clientsocket.close()
        print("Connection closed: %s" % str(addr))


# ---------- MAIN ----------
# Make sure the storage folder exists
if not os.path.exists(SERVER_ROOT):
    os.mkdir(SERVER_ROOT)

# create a socket object
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# bind to the port
serversocket.bind((HOST, PORT))

# queue up to 5 requests
serversocket.listen(5)
print("RFMP server listening on port %d" % PORT)

while True:
    # establish a connection
    clientsocket, addr = serversocket.accept()

    # new thread for each client
    thread1 = threading.Thread(target=handle_client, args=(clientsocket, addr))
    thread1.start()
