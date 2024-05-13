import socket
import json
import base64
import threading
import os
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import dh, rsa, utils, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as paddin
import zlib

# Function to handle receiving messages
def receive_messages(client_socket,their_public_key,my_private_key):
    while True:
        try:
            encrypted_json_message = client_socket.recv(2048)
            if not encrypted_json_message:
                break  # Connection closed by the other side
            received_json_message = encrypted_json_message.decode()
            received_json_message = json.loads(received_json_message)

            # Decrypt the session key using RSA
            aes_key = rsa_decrypt(my_private_key, base64.b64decode(received_json_message["session_key"]))

            # Decompress the message
            compressed_message = base64.b64decode(received_json_message["message"])
            decompressed_message = zlib.decompress(compressed_message)

            # Decrypt the message using AES
            decrypted_message = aes_decrypt(aes_key, decompressed_message).decode()

           # Extract the original JSON message
            received_json = json.loads(decrypted_message)
            received_message = received_json["message"]
            received_signature_base64 = received_json["signature"]
            received_signature_bytes = base64.b64decode(received_signature_base64.encode('utf-8'))
            print(f"Received: {received_message}")

            # Verify the signature
            verified = verify_signature(their_public_key, received_signature_bytes, received_message.encode())
            if verified:
                print("Verified Signature!")
            else:
                print("Could not verify Signature!")

        except Exception as e:
            print(f"Error receiving message: {e}")
            break

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

# Function to handle sending messages
def send_message(client_socket,private_key,public_key):
    while True:
        message = input()        
        # First, we sign the message
        signature = rsa_sign(message.encode(),private_key)
        signature_base64 = base64.b64encode(signature).decode('utf-8')
        json_message = {
            "message": message,
            "signature": signature_base64
        }
        json_string = json.dumps(json_message).encode()

        # Generate session key
        aes_key = os.urandom(32)
        session_key = rsa_encrypt(public_key,aes_key)

        encrypted_message = aes_encrypt(aes_key, json_string)
        compressed_message = zlib.compress(encrypted_message)
        compressed_message_base64 = base64.b64encode(compressed_message).decode('utf-8')
        session_key_base64 = base64.b64encode(session_key).decode('utf-8')

        final_json_message = {
            "session_key": session_key_base64,
            "message": compressed_message_base64
        }
        final_json_string = json.dumps(final_json_message).encode()

        client_socket.sendall(final_json_string)
        if message.strip() == "/quit":
            print("Connection ended.")
            break

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

# Function to generate new RSA key pair
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Function to save keys to JSON file
def save_my_keys_to_json(private_key, public_key, password, key_id):
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

# Function to save keys to JSON file
def save_their_keys_to_json(name, public_key, key_id, certificate):
    with open('keys.json', 'r') as json_file:
        data = json.load(json_file)

    public_key_serialized = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Convert the serialized keys to strings
    public_key_string = public_key_serialized.decode('utf-8')

    # Create a dictionary with the keys
    new_key = {
        "id": key_id,
        "name": name,
        "public_key": public_key_string,
        "certificate": certificate
    }

    data['other_keys'].append(new_key)

    # Write the dictionary to a JSON file
    with open('keys.json', 'w') as json_file:
        json.dump(data, json_file, indent=4)

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

# Main function to establish connection and start threads for sending and receiving messages
def main():
    # Define host and port to bind to
    host = "127.0.0.1"
    port = 5555

    password = input("Enter a password to protect the private key: ")
    key_id = input("What is the ID of the key you want to use: ")
        
    # Load keys from JSON file
    private_key, public_key = load_keys_from_json(password, key_id)

    if private_key and public_key:
        print("Keys loaded from JSON file.")
    else:
        # Generate new key pair
        private_key, public_key = generate_key_pair()
        print("New keys generated.")
        save_my_keys_to_json(private_key, public_key, password, key_id)

    # Use the keys as needed
    print("Private Key:", private_key)
    print("Public Key:", public_key)

    # Create a TCP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Ask user if they want to initiate connection or wait for connection
    mode = input("Enter 'i' to initiate connection or 'w' to wait for connection: ")

    if mode.lower() == "i":
        # Get IP address and port of the other client
        remote_ip = input("Enter IP address of the other client: ")
        remote_port = int(input("Enter port number of the other client: "))

        # Connect to the other client
        try:
            client_socket.connect((remote_ip, remote_port))
            print("Connected to the other client.")
        except Exception as e:
            print(f"Error connecting to the other client: {e}")
            return
    elif mode.lower() == "w":
        # Bind the socket to the host and port
        try:
            client_socket.bind((host, port))
            print("Waiting for connection...")
        except Exception as e:
            print(f"Error binding socket: {e}")
            return

        # Listen for incoming connections
        client_socket.listen(1)

        # Accept incoming connection
        client_socket, client_address = client_socket.accept()
        print(f"Connection established with {client_address}")

    else:
        print("Invalid mode. Please enter 'initiate' or 'wait'.")
        return

    # Start thread to receive messages
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,public_key,private_key))
    receive_thread.start()

    # Start thread to send messages
    send_thread = threading.Thread(target=send_message, args=(client_socket,private_key,public_key))
    send_thread.start()

if __name__ == "__main__":
    main()
