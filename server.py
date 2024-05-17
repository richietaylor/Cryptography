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
import random
from cryptography.hazmat.primitives.asymmetric import padding


SERVER_HOST = 'localhost'
SERVER_PORT = 12000
BLOCK_SIZE = 2048           # Block sizes to read from the file at a time
CONNECTIONS = {}
CHALLENGES = {}

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
                handle_message(connection, data, message['recipient'], username)

            elif message_type == "NOW ONLINE":
                send_stored_messages(connection, username, message['sender'])

            elif message_type == "FILE":
                print("Receiving a file...")
                user = message['user']
                handle_file(connection, message, username)
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
    client_public_key_pem = message["public_key"]
    client_public_key = serialization.load_pem_public_key(client_public_key_pem.encode('utf-8'))

    # Generate a random challenge
    challenge = random.randint(100000, 999999)
    CHALLENGES[username] = challenge

    # Encrypt the challenge with the client's public key
    encrypted_challenge = client_public_key.encrypt(
        str(challenge).encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Send the encrypted challenge to the client
    challenge_response = {"message_type": "CERTIFICATE CHALLENGE", "challenge": base64.b64encode(encrypted_challenge).decode('utf-8')}
    connection.sendall(json.dumps(challenge_response).encode())



def handle_challenge_response(connection, username, message):
    client_response = message["challenge_response"]

    if username in CHALLENGES and CHALLENGES[username] == int(client_response):
        print(f"Challenge successful for {username}")

        # Load the client's public key from the earlier request
        client_public_key_pem = message["public_key"]
        client_public_key = serialization.load_pem_public_key(client_public_key_pem.encode('utf-8'))

        certificate_pem = create_client_certificate(client_public_key, ca_private_key, username)
        cert_response = {"message_type": "CERTIFICATE", "certificate": certificate_pem.decode('utf-8')}
        connection.sendall(json.dumps(cert_response).encode())
    else:
        print(f"Challenge failed for {username}")
        connection.sendall(json.dumps({"message_type": "CERTIFICATE", "certificate": "CHALLENGE FAILED"}).encode())

# A function that relays a message from one client to another without decrypting it
def handle_message(connectionFrom, data, recipient, sender):
    """Relays a message from one client to another."""
    if recipient in CONNECTIONS:
        relay_message(CONNECTIONS[recipient], data)
    else:
        print(f"User {recipient} not connected or does not exist.")
        store_message(recipient, data, sender)
        print(f"Message stored for {recipient}")
    return

def relay_message(connectionTo, data):
    connectionTo.sendall(data)
    return

def handle_file(connection, message, username):
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
        store_file(recipient, file_name, file_data, username)
        print(f"File stored for {recipient}")


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

# Store file in the server in a JSON file named saved_messages
# The file is stored in the format recipient : {sender: {files: [{file_name: file_data}]; messages: [message]}}
def store_file(recipient, file_name, file_data, sender):
    """Store file in the server."""
    if not os.path.exists("../database/saved_messages"):  # Create a database if it does not exist
        os.makedirs("../database/saved_messages")

    if not os.path.exists(f"../database/saved_messages/{recipient}_files.json"):  # Create a file if it does not exist
        with open(f"../database/saved_messages/{recipient}_files.json", "w") as f:
            f.write("{}")

    with open(f"../database/saved_messages/{recipient}_files.json", "r+") as f:
        store_files = json.load(f)
        if sender in store_files:
            store_files[sender]["files"].append({"file_name": file_name, "file_data": file_data})
        else:
            store_files[sender] = {"files": [{"file_name": file_name, "file_data": file_data}]}
        f.seek(0)
        json.dump(store_files, f, indent=4, separators=(',', ': '))
        f.write('\n')

# Store messages in the server in a JSON file named saved_messages
# The message is stored in the format recipient : {sender: {files: [{file_name: file_data}], messages: [message]}}
def store_message(recipient, message, sender):
    """Store message in the server."""
    if not os.path.exists("../database/saved_messages"):  # Create a database if it does not exist
        os.makedirs("../database/saved_messages")

    if not os.path.exists(f"../database/saved_messages/{recipient}_messages.json"):  # Create a file if it does not exist
        with open(f"../database/saved_messages/{recipient}_messages.json", "w") as f:
            f.write("{}")

    with open(f"../database/saved_messages/{recipient}_messages.json", "r+") as f:
        store_messages = json.load(f)
        if sender in store_messages:
            store_messages[sender]["messages"].append(message)
        else:
            store_messages[sender] = {"messages": [message]}
        f.seek(0)
        json.dump(store_messages, f, indent=4, separators=(',', ': '))
        f.write('\n')

# Retrieve files from the server, and delete them from the server, 
# storing them in a dictionary with file name as key
# and file data as value

def retrieve_files(username, sender):
    """Retrieve files from the server."""
    files = {}
    if not os.path.exists(f"../database/files/{username}_files.json"):
        return files

    with open(f"../database/files/{username}_files.json", "r+") as f:
        store_files = json.load(f)
        if sender in store_files:
            for file in store_files[sender]["files"]:
                files[file["file_name"]] = file["file_data"]
            del store_files[sender]
            f.seek(0)
            json.dump(store_files, f, indent=4, separators=(',', ': '))
            f.write('\n')
    return files

# Retrieve messages from the server, and delete them from the server,
# storing them in a list

def retrieve_messages(username, sender):
    """Retrieve messages from the server."""
    messages = []
    if not os.path.exists(f"../database/messages/{username}_messages.json"):
        return messages

    with open(f"../database/messages/{username}_messages.json", "r+") as f:
        store_messages = json.load(f)
        if sender in store_messages:
            messages = store_messages[sender]["messages"]
            del store_messages[sender]
            f.seek(0)
            json.dump(store_messages, f, indent=4, separators=(',', ': '))
            f.write('\n')
    return messages

def send_stored_messages(connection, username, sender):
    """Send stored messages to the client."""
    files = retrieve_files(username, sender)
    messages = retrieve_messages(username, sender)

    for file_name, file_data in files.items():
        relay_file(connection, file_name, file_data)
    for message in messages:
        relay_message(connection, message)
    return

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
