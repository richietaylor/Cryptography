import os
import threading
import socket
import json
import hashlib
import base64
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import dh, rsa, utils, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as paddin
import zlib
import tempfile
from cryptography import x509

# TODO remove uneccessary imports

# Constants

SERVER_HOST = "localhost"
SERVER_PORT = 12000
BLOCK_SIZE = 2048           # Block sizes to read from the file at a time

# Globals
USERNAME = ""
terminate_flag = False

def main():
    """"Connecting to the server"""
    connecting = True
    while connecting:
        try:
            clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            clientSocket.connect((SERVER_HOST, SERVER_PORT))
            connecting = False
        except Exception as e:
            print("Error: You are not connected to the server")
    global USERNAME
    global terminate_flag

    isAuthenticated = False

    while not isAuthenticated:
        username = input("Please enter your username:\n>>> ")
        password = input("Please enter your password:\n>>> ")
        key_id = ''

        # send the username and password to the server
        auth_obj = {
            "message_type": "AUTH",
            "username": username,
            "password": password,
        }

        clientSocket.sendall(json.dumps(auth_obj).encode())

        # receive the response from the server
        response = clientSocket.recv(BLOCK_SIZE).decode()
        auth_info = json.loads(response)

        if auth_info["message_type"] == "AUTH NEW USER":
            print("Welcome, " + username)
            key_id = auth_info["key_id"]
            print(f"Key ID: {key_id}")
            isAuthenticated = True

        elif auth_info["message_type"] == "AUTHENTICATION CONFIRMATION":
            if auth_info["result"] == "yes":
                print("Welcome", username)
                USERNAME = username
                key_id = auth_info["key_id"]
                print(f"Key ID: {key_id}")
                isAuthenticated = True
            else:
                print("Authentication failed. Please try again.\nIf this is your first login, the username may be taken")
                continue
        
        # Load keys from JSON file
        #print(password, key_id)
        private_key, public_key = load_keys_from_json(password, key_id)

        if private_key and public_key:
            print("Keys loaded from JSON file.")
        else:
            # Generate new key pair
            private_key, public_key = generate_key_pair()
            print("New keys generated.")
            update_public_key_on_server(clientSocket, username, public_key)
            save_my_keys_to_json(private_key, public_key, password, key_id)

        request_certificate(clientSocket, private_key, public_key, username)
    
    menu(clientSocket, private_key, password, key_id)
    clientSocket.close()


def menu(clientSocket, private_key, password, my_key):
    while True:
        input("\n-Press RETURN to continue")
        # Uncomment for Linux
        os.system('clear')
        # os.system('cls') 
        print("\nEnter the name of the person you want to send a message to")
        print("\nInput a command number and press RETURN:\n   \
              1 - Enter Chat\n   \
              2 - List all users\n   \
              3 - List Files\n   \
              4 - Delete File\n   \
              5 - Change Directory\n   \
              0 - Quit")
        command = input(">>> ").strip()

        if command == "1":
            # Enter Chat
            print("Enter the user name")
            user = input(">>> ").strip()
            
            # check with server if user exists and return the public key and key_id
            user_check = {
                "message_type": "USER CHECK",
                "username": user
            }

            clientSocket.sendall(json.dumps(user_check).encode())
            response = clientSocket.recv(BLOCK_SIZE).decode()
            user_info = json.loads(response)

            if user_info["message_type"] == "USER CHECK RESPONSE":
                if user_info["result"] == "yes":
                    print("User exists.")
                    print(user_info["public_key"])
                    chat(clientSocket, user, private_key, user_info["public_key"], user_info["key_id"], password, my_key)
                    terminate_flag = False
                else:
                    print("User does not exist.")
        elif command == "2":
            # Request list of users from the server and print them
            user_list_request = {
                "message_type": "LIST"
            }
            clientSocket.sendall(json.dumps(user_list_request).encode())
            # Receive the list of users
            response = clientSocket.recv(BLOCK_SIZE).decode()
            user_list_response = json.loads(response)
            if user_list_response["message_type"] == "USER LISTING":
                users = user_list_response["users"]
                print("Available users:")
                for user in users:
                    print("\t", user)

        elif command == "3":
            files = os.listdir()
            out = ""
            for item in files:
                out += item + "\n"
            print("Local Directory: \n")
            print(out)
        elif command == "4":
            try:
                file = input("Enter File Name: ")
                os.remove(file)
                print("Successfully Deleted File.")
            except FileNotFoundError:
                print("ERROR 404 - File not found")
        elif command == "5":
            # @TODO Change Dir Files
            print("TODO - Change Dir")

        elif command == "6":
            print("TODO - Get certificate")
            # requestCertificate()

        elif command == "0":
            break
        else:
            print("Invalid command. Please try again.")

    return


def chat(serverSocket, user, private_key, public_key, key_id, password, my_key):
    global terminate_flag
    deserialize_public_key = serialization.load_pem_public_key(public_key.encode('utf-8'))
    
    other_user_cert_pem = request_other_client_certificate(serverSocket, user)
    if not other_user_cert_pem:
        print("Cannot proceed with chat due to invalid certificate.")
        return
    
    
    listenThread = threading.Thread(target=receiveMessage, args=(serverSocket, private_key, deserialize_public_key, key_id, password, my_key,))
    listenThread.start()
    print(user)
    print("Enter 0 to quit the chat.\nEnter 1 to send a file.")
    while True:
        message = input(">>> ")
        if message.isdigit() and eval(message) == 0:
            terminate_flag = True
            break
        if message.isdigit() and eval(message) == 1:
            filepath = input("Please enter the name of the file: ")
            sendFile(serverSocket, filepath, user, private_key, deserialize_public_key, key_id)
        else:
            sendMessage(serverSocket, message, user, private_key, deserialize_public_key, key_id)
    return


def request_other_client_certificate(client_socket, other_username):
    cert_request = {
        "message_type": "CERTIFICATE REQUEST",
        "username": other_username
    }
    client_socket.sendall(json.dumps(cert_request).encode())

    response = client_socket.recv(BLOCK_SIZE).decode()
    cert_response = json.loads(response)

    if cert_response["message_type"] == "CERTIFICATE RESPONSE":
        other_client_cert_pem = cert_response["certificate"]
        print(f"Received {other_username}'s certificate:\n{other_client_cert_pem}")

        with open(f"{other_username}_certificate.pem", "w") as f:
            f.write(other_client_cert_pem)
        
        verified = verify_certificate(other_client_cert_pem, "ca_public_key.pem")
        if verified:
            print(f"{other_username}'s certificate is valid.")
            return other_client_cert_pem
        else:
            print(f"{other_username}'s certificate is invalid.")
            return None
    else:
        print("Failed to receive the other client's certificate.")
        return None


def receiveMessage(clientSocket, private_key, public_key, key_id, password, my_key):
    """Receive messages or files from the server."""
    global terminate_flag
    while not terminate_flag:
        try:
            # Read the initial data which could be a message or file metadata
            data = clientSocket.recv(BLOCK_SIZE).decode()
            message = json.loads(data)
            print(message)
            if message["message_type"] == "MESSAGE":
                # Decrypt and display the message
                decrypted_message = decrypt_message(message["message"], private_key, public_key, my_key, password)
                print(f"Message received: {decrypted_message}")
            elif message["message_type"] == "FILE":
                receive_file(clientSocket, message, private_key, public_key, key_id, password, my_key)
            
        except json.JSONDecodeError:
            continue  # If it fails, it might be part of file data still being received.
        except Exception as e:
            print("An error occurred:", e)
            break


def receive_file(clientSocket, file_info, private_key, public_key, key_id, password, my_key):
    """Receive a file based on received metadata."""
    try:
        file_name = file_info["file_name"]
        file_size = file_info["file_size"]
        path = f"{USERNAME}_received_files/{file_name}"
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        received_data = b""
        while file_size > 0:
            chunk = clientSocket.recv(min(BLOCK_SIZE, file_size))
            if not chunk:
                break
            received_data += chunk
            file_size -= len(chunk)
        
        print(f"File '{file_name}' received.")
        
        # Decrypt the received data as a string
        decrypted_string = decrypt_message(received_data.decode('utf-8'), private_key, public_key, my_key, password)
        if decrypted_string:
            # Convert the decrypted string back to binary data
            decrypted_content = base64.b64decode(decrypted_string)
            
            # Write the decrypted content to the final file
            with open(path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_content)
            print(f"File '{file_name}' decrypted and saved to '{path}'.")
        else:
            print("Failed to decrypt file.")
    except Exception as e:
        print(f"An error occurred while receiving file: {e}")


def sendMessage(serverSocket, message, user, private_key, public_key, key_id):
    """Send a message to the server."""
    # Encrypt message here
    encrypted_message = encrypt_message(message, private_key, public_key, key_id)
    message_obj = {
        "message_type": "MESSAGE",
        "message": encrypted_message,
        "username": USERNAME,
        "user": user,
    }
    print(message_obj)
    serverSocket.sendall(json.dumps(message_obj).encode())
    return


def sendFile(serverSocket, filepath, user, private_key, public_key, key_id):
    """Send a file to the server."""
    try:
        # Encrypt the file
        with open(filepath, 'rb') as file:
            binary_data = file.read()
        base64_data = base64.b64encode(binary_data).decode('ascii')
        encrypted_data = encrypt_message(base64_data, private_key, public_key, key_id)

        message_obj = {
            "message_type": "FILE",
            "username": USERNAME,
            "user": user,
            "file_name": os.path.basename(filepath),
            "file_size": len(encrypted_data)
        }
        serverSocket.sendall(json.dumps(message_obj).encode())
        serverSocket.sendall(encrypted_data.encode())
        print("File sent successfully.")
    except Exception as e:
        print(f"Failed to send file: {e}")


def request_certificate(client_socket, private_key, public_key, username):
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    cert_request = {
        "message_type": "CERTIFICATE",
        "username": username,
        "public_key": public_key_pem
    }
    client_socket.sendall(json.dumps(cert_request).encode())

    response = client_socket.recv(BLOCK_SIZE).decode()
    cert_response = json.loads(response)

    if cert_response["message_type"] == "CERTIFICATE":
        certificate_pem = cert_response["certificate"]
        print(f"Received certificate from CA:\n{certificate_pem}")

        with open(f"{username}_certificate.pem", "w") as f:
            f.write(certificate_pem)
    else:
        print("Failed to receive certificate from CA.")


def exchange_certificates(client_socket, other_user):
    # Request the other user's certificate
    cert_request = {
        "message_type": "CERTIFICATE REQUEST",
        "username": other_user
    }
    client_socket.sendall(json.dumps(cert_request).encode())

    response = client_socket.recv(BLOCK_SIZE).decode()
    cert_response = json.loads(response)

    if cert_response["message_type"] == "CERTIFICATE RESPONSE":
        other_user_cert_pem = cert_response["certificate"]
        print(f"Received {other_user}'s certificate:\n{other_user_cert_pem}")

        with open(f"{other_user}_certificate.pem", "w") as f:
            f.write(other_user_cert_pem)
        
        # Verify the certificate (optional)
        other_user_cert = x509.load_pem_x509_certificate(other_user_cert_pem.encode('utf-8'))
        verify_certificate(other_user_cert)
    else:
        print("Failed to receive the other user's certificate.")


def verify_certificate(certificate_pem, ca_public_key_file):
    with open(ca_public_key_file, "rb") as f:
        ca_public_key = serialization.load_pem_public_key(f.read())

    certificate = x509.load_pem_x509_certificate(certificate_pem.encode('utf-8'))

    try:
        ca_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
        # print("Certificate is valid.")
        return True
    except Exception as e:
        print("Certificate verification failed:", e)
        return False


def encrypt_message(message, private_key, public_key, key_id):
    """Encrypt the message."""
     # First, we sign the message
    signature = rsa_sign(message.encode(),private_key)
    signature_base64 = base64.b64encode(signature).decode('utf-8')
    print(f"Signed message!")
    json_message = {
        "message": message,
        "signature": signature_base64
    }
    print(f"Constructed Object: {json_message}")
    json_string = json.dumps(json_message).encode()

    # Generate session key
    aes_key = os.urandom(32)
    print(f"Generated AES key: {aes_key}")
    session_key = rsa_encrypt(public_key,aes_key)
    print("Encrypted session key with public key!")
    encrypted_message = aes_encrypt(aes_key, json_string)
    compressed_message = zlib.compress(encrypted_message)
    compressed_message_base64 = base64.b64encode(compressed_message).decode('utf-8')
    session_key_base64 = base64.b64encode(session_key).decode('utf-8')
    final_json_message = {
        "key_id": key_id, # TODO - Implement this
        "session_key": session_key_base64,
        "message": compressed_message_base64
    }
    print(f"Constructed Object: {final_json_message}")
    final_json_string = json.dumps(final_json_message).encode()
    encrypted_message_base64 = base64.b64encode(final_json_string).decode('utf-8')
    print("Sending Message...")
    return encrypted_message_base64


def decrypt_message(message, private_key, public_key, key_id,password):
    """Decrypt the message."""
    decoded_message = base64.b64decode(message)
    received_json_message = json.loads(decoded_message)
    print(f"Received Message: {received_json_message}")
    
    # Decrypt the session key using RSA
    message_key_id = received_json_message["key_id"]
    rsa_private_key = get_key_from_id(message_key_id,password)
    aes_key = rsa_decrypt(rsa_private_key, base64.b64decode(received_json_message["session_key"]))
    print(f"Decrypted AES key: {aes_key}")

    # Decompress the message
    compressed_message = base64.b64decode(received_json_message["message"])
    decompressed_message = zlib.decompress(compressed_message)
    print(f"Decompressed Message: {decompressed_message}")
    # Decrypt the message using AES
    decrypted_message = aes_decrypt(aes_key, decompressed_message).decode()

    # Extract the original JSON message
    received_json = json.loads(decrypted_message)
    print(f"Decrypted Message with public key: {received_json}")
    received_message = received_json["message"]
    received_signature_base64 = received_json["signature"]
    received_signature_bytes = base64.b64decode(received_signature_base64.encode('utf-8'))
    # Verify the signature
    verified = verify_signature(public_key, received_signature_bytes, received_message.encode())
    if verified:
        print("Verified Signature!")
    else:
        print("Could not verify Signature!")

    return received_message


def verify_signature(public_key, signature, message):
    try:
        # Verify the signature
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        # Signature verification succeeded
        return True
    except Exception as e:
        # Signature verification failed
        return False
        

def rsa_sign(message,private_key):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def rsa_encrypt(public_key, message):
    # Use RSA encryption to encrypt the plaintext
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def rsa_decrypt(private_key, ciphertext):
    # Use RSA decryption to decrypt the ciphertext
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def aes_encrypt(key, plaintext):
    # Generate a random initialization vector (IV)
    iv = os.urandom(16)
    # Create a cipher object using AES in CBC mode with the provided key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    # Create a padder for padding the plaintext
    padder = paddin.PKCS7(algorithms.AES.block_size).padder()
    # Pad the plaintext
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    # Create an encryptor object
    encryptor = cipher.encryptor()
    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(key, ciphertext):
    # Extract the IV from the ciphertext (first 16 bytes)
    iv = ciphertext[:16]
    # Extract the encrypted data (excluding the IV)
    encrypted_data = ciphertext[16:]
    # Create a cipher object using AES in CBC mode with the provided key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    # Create a decryptor object
    decryptor = cipher.decryptor()
    # Decrypt the ciphertext
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    # Create an unpadder for removing padding
    unpadder = paddin.PKCS7(algorithms.AES.block_size).unpadder()
    # Unpad the decrypted data
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data

# Function to generate new RSA key pair
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def update_public_key_on_server(client_socket, username, public_key):
    public_key_serialized = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_string = public_key_serialized.decode('utf-8')

    update_public_key = {
        "message_type": "UPDATE PUBLIC KEY",
        "username": username,
        "public_key": public_key_string,
    }
    client_socket.sendall(json.dumps(update_public_key).encode())

# Function to save keys to JSON file
def save_my_keys_to_json(private_key, public_key, password, key_id):
    # check if the file exists
    if not os.path.exists('keys.json'):
        # Create a new JSON file
        with open('keys.json', 'w') as json_file:
            data = {
                "my_keys": [],
            }
            json.dump(data, json_file, indent=4)

    with open('keys.json',   'r') as json_file:
        data = json.load(json_file)

    private_key_serialized = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )
    public_key_serialized = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Convert the serialized keys to strings
    private_key_string = private_key_serialized.decode('utf-8')
    public_key_string = public_key_serialized.decode('utf-8')

    # Create a dictionary with the keys
    new_key = {
        "id": key_id,
        "private_key": private_key_string,
        "public_key": public_key_string
    }

    data['my_keys'].append(new_key)

    # Write the dictionary to a JSON file
    with open('keys.json', 'w') as json_file:
        json.dump(data, json_file, indent=4)

def get_key_from_id(key_id,password):
    """ Loads the RSA key that corresponds to the ID sent in a message """
    if os.path.exists('keys.json'):
        with open('keys.json', 'r') as json_file:
            keys_dict = json.load(json_file)
            for key in keys_dict['my_keys']:
                if key['id'] == key_id:
                    private_key_bytes = key['private_key']
                    if private_key_bytes:
                        private_key = serialization.load_pem_private_key(
                            private_key_bytes.encode('utf-8'),
                            password=password.encode(),
                        )
                        return private_key
    return None

# Function to load keys from JSON file
def load_keys_from_json(password,key_id):
    if os.path.exists('keys.json'):
        with open('keys.json', 'r') as json_file:
            keys_dict = json.load(json_file)
            for key in keys_dict['my_keys']:
                if key['id'] == key_id:
                    private_key_bytes = key['private_key']
                    public_key_bytes = key['public_key']
                    if private_key_bytes and public_key_bytes:
                        private_key = serialization.load_pem_private_key(
                            private_key_bytes.encode('utf-8'),
                            password=password.encode(),
                        )
                        public_key = serialization.load_pem_public_key(
                            public_key_bytes.encode('utf-8'),
                        )
                        return private_key, public_key
    return None, None

if __name__ == '__main__':
    main()
