import socket
import os
import json
import concurrent.futures as thread_pool
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime
from cryptography.hazmat.primitives.serialization import load_pem_private_key


SERVER_HOST = 'localhost'
SERVER_PORT = 12000
BLOCK_SIZE = 2048           # Block sizes to read from the file at a time
CONNECTIONS = {}

def authenticate_user(connection, username, password):
    """Reads from database to determine if user exists, creates a new entry if they don't."""
    if not os.path.exists("../database"):  # Create a database if it does not exist
        os.makedirs("../database")
    # Create a json file if it does not exist
    if not os.path.exists("../database/users.json"):
        with open("../database/users.json", "w") as f:
            f.write("{}")

    # Flag to determine if the user exists or not
    user_exists = False
    users = {}

    # Reads from a file that has all known users
    # Search for a user with the given username
    with open("../database/users.json", "r") as file:
        users = json.load(file)

        for user in users:
            if user == username:
                user_exists = True
                break

    if not user_exists:  # If it is a new user, they are registered
        return register_user(connection, username, password)

    else:
        if password == users[username]["password"]:
            print(f"Authentication Successful")
            return "Authentication Successful"

        else:
            # Send authentication failed message
            print("Authentication failed because password didn't match")
            return "Authentication Error"


def generate_ca_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_ca_keys_to_files(private_key, public_key, private_key_file="ca_private_key.pem", public_key_file="ca_public_key.pem"):
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(private_key_file, 'wb') as f:
        f.write(pem_private)
    with open(public_key_file, 'wb') as f:
        f.write(pem_public)


def create_client_certificate(client_public_key, ca_private_key, username):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])
    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        client_public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(username)]),
        critical=False,
    ).sign(ca_private_key, hashes.SHA256())

    return certificate.public_bytes(serialization.Encoding.PEM)


def register_user(connection, username, password):
    """Adds a new user to the record of users"""
    print(username, password)
    # Alert the client that the user is new
    auth_obj = {
        "message_type": "AUTH NEW USER",
    }

    connection.sendall(json.dumps(auth_obj).encode())

    # Add the user to the file
    with open("../database/users.json", "r+") as f:
        users = json.load(f)

        users[username] = {
            "password": password,
        }

        f.seek(0)  # sets the file pointer position to the beginning of the file
        json.dump(users, f, indent=4, separators=(',', ': '))
        f.write('\n')
    return "Authentication Successful"


def list_users(connection):
    """Lists all users that are registered"""
    users = []
    with open("../database/users.json", "r") as file:
        users = json.load(file)

    data = {
        "message_type": "USER LISTING",
        "body": users
    }
    json_object = json.dumps(data)
    connection.sendall(json_object.encode())
    print("File list sent to client")


def user_auth(connection):
    """Handles an incoming client request."""

    AUTHENTICATED = False
    username = ""
    password = ""

    while not AUTHENTICATED:
        # Authenticate the user first
        data = connection.recv(BLOCK_SIZE)
        json_object = data.decode()
        message = json.loads(json_object)

        if message["message_type"] == "AUTH":  # Authentication message
            username = message["username"]
            password = message["password"]

            auth_result = authenticate_user(connection, username, password)

            auth_response = ""
            if auth_result == "Authentication Error":
                print(f"Auth failed")

                # Send an authentication error
                auth_response = {
                    "message_type": "AUTHENTICATION CONFIRMATION",
                    "result": "no"
                }
            elif auth_result == "Authentication Successful":
                AUTHENTICATED = True

                auth_response = {
                    "message_type": "AUTHENTICATION CONFIRMATION",
                    "result": "yes"
                }
                CONNECTIONS[username] = connection

            json_data = json.dumps(auth_response)
            connection.sendall(json_data.encode())
    handle_requests(connection, username)
    return


def handle_requests(connection, username):
    """Handles incoming client requests."""
    # Command input loop
    while True:
        print(f"Waiting for command...")
        try:
            connection.getpeername()  # Checks if the connection still open, if not, kill the thread

            # Get next message
            data = connection.recv(BLOCK_SIZE)

            json_object = data.decode().strip()
            message = json.loads(json_object)
            message_type = message["message_type"]
            print(f"Command Received: {message_type}")

            if message_type == "LIST":
                list_users(connection)

            elif message_type == "MESSAGE":
                relay_message(connection, data, message['user'])

            elif message_type == "FILE":
                print("Receiving a file...")
                user = message['user']
                handle_file(connection, message)
            elif message_type == "CERTIFICATE":
                # print(f"Got a request from {username}...")
                handle_certificate_request(connection, username, message)
                print(f"{username} given certificate")
            elif message_type == "CERTIFICATE REQUEST":
                handle_certificate_exchange(connection, username, message)
            elif message_type == "QUIT":
                print(f"User \"{username}\" disconnected")
                connection.close()
                break

        except (BrokenPipeError, ConnectionResetError):
            print(f'Error: Connection lost')
            break
    return


def handle_certificate_exchange(connection, username, message):
    other_user = message["username"]
    with open(f"{other_user}_certificate.pem", "r") as f:
        certificate_pem = f.read()

    cert_response = {
        "message_type": "CERTIFICATE RESPONSE",
        "certificate": certificate_pem
    }
    connection.sendall(json.dumps(cert_response).encode())


def handle_certificate_request(connection, username, message):
    print("Begin")
    client_public_key_pem = message["public_key"]
    client_public_key = serialization.load_pem_public_key(client_public_key_pem.encode('utf-8'))
    certificate_pem = create_client_certificate(client_public_key, ca_private_key, username)

    cert_response = {
        "message_type": "CERTIFICATE",
        "certificate": certificate_pem.decode('utf-8')
    }
    connection.sendall(json.dumps(cert_response).encode())


# A function that relays a message from one client to another without decrypting it
def relay_message(connectionFrom, data, user):
    """Relays a message from one client to another."""
    connectionTo = CONNECTIONS[user]
    connectionTo.sendall(data)
    return


def handle_file(connection, message):
    """Handle file received from the client."""
    file_name = message['file_name']
    file_size = int(message['file_size'])
    recipient = message['user']

    # Collect file data from sender
    file_data = b''
    while file_size > 0:
        data = connection.recv(min(BLOCK_SIZE, file_size))
        if not data:
            break
        file_data += data
        file_size -= len(data)
    
    print(f"Received file: {file_name}")
    # Relay file to the intended recipient
    if recipient in CONNECTIONS:
        relay_file(CONNECTIONS[recipient], file_name, file_data)
    else:
        print(f"Recipient {recipient} not connected or does not exist.")


def relay_file(connectionTo, file_name, data):
    """Relay the file to another client."""
    try:
        # Send file metadata first
        message_obj = {
            "message_type": "FILE",
            "file_name": file_name,
            "file_size": len(data)
        }
        connectionTo.sendall(json.dumps(message_obj).encode())
        connectionTo.sendall(data)
        print("File relayed successfully to recipient.")
    except Exception as e:
        print(f"Failed to relay file: {e}")


def listen_for_exit_command():
    """Listen for 'exit' command from the console to stop the server."""
    while True:
        user_input = input("Type 'exit' to stop the server:\n")
        if user_input.lower() == 'exit':
            print("Stopping server...")
            for connection in CONNECTIONS:
                CONNECTIONS[connection].close()
            os._exit(0)
    

def load_ca_private_key(private_key_file="ca_private_key.pem"):
    with open(private_key_file, "rb") as key_file:
        private_key = load_pem_private_key(
            key_file.read(),
            password=None,
        )
    return private_key



def main():

    global ca_private_key #make caps
    ca_private_key = load_ca_private_key()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clientSocket:
        clientSocket.bind((SERVER_HOST, SERVER_PORT))
        clientSocket.listen(10)

        print(f'Server listening on {SERVER_HOST}: {SERVER_PORT}...')

        
        ca_private_key, ca_public_key = generate_ca_keys()
        save_ca_keys_to_files(ca_private_key, ca_public_key)
        print("CA Keys generated")

        # Create a thread pool with 5 threads
        pool = thread_pool.ThreadPoolExecutor(max_workers=5)
        
        pool.submit(listen_for_exit_command)

        while True:
            connection, address = clientSocket.accept()

            print(f'Client connected from {address[0]} :{address[1]}')
            # Assigning a new connection to a thread
            pool.submit(user_auth, connection)


if __name__ == '__main__':
    main()
