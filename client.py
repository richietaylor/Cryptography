import socket
import json
import base64
import threading
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import dh, rsa, utils, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import socket

# Global variables to store the certificate and server public key
certificate = None
server_public_key = None

def receive_messages(sock,my_public_key_serialised):
    global certificate, server_public_key
    
    while True:
        try:
            message = sock.recv(1024).decode('utf-8')
            if message:
                print("\rReceived from server: " + message)
                # Parse the message as JSON
                data = json.loads(message)
                # Check if the message contains the certificate and server public key
                if "certificate" in data and "server_public_key" in data:
                    # Store the certificate and server public key
                    certificate = base64.b64decode(data["certificate"])
                    server_public_key = serialization.load_pem_public_key(data["server_public_key"].encode())
                    print("Certificate and server public key received.")
                    # Verify the certificate
                    if verify_certificate(certificate,my_public_key_serialised):
                        print("Successfully able to verify own certificate.")
                    else:
                        print("Unable to verify own certificate.")
                
                elif message.strip().lower() == 'exit':
                    print("\nExiting...")
                    sock.close()
                    break
        except Exception as e:
            print("Exception:", e)
            print("You have been disconnected from the server")
            sock.close()
            break


def verify_certificate(certificate,my_public_key_serialised):
    global server_public_key
    try:
        # Verify the signature using the server's public key
        server_public_key.verify(
            certificate,
            my_public_key_serialised,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Certificate verification error: {e}")
        return False

def send_messages(sock, my_public_key_serialised, ip, port):
    # First send our public key, IP, and Port Number
    init_message = json.dumps({"public_key": my_public_key_serialised.decode(), "ip": ip, "port": port}).encode()
    try:
        sock.send(init_message)
    except:
        print("Failed to send initial message")
        sock.close()
        return

    while True:
        message = input("Message: ")
        try:
            sock.send(message.encode('utf-8'))
            if message.strip().lower() == 'exit':
                print("\nExiting...")
                sock.close()
                break
        except:
            print("Failed to send message")
            sock.close()
            break

def main():
    # Generate a public and private key pair.
    my_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=512,
    )
    my_public_key = my_private_key.public_key()
    # Need to serialize the public key before we can send it.
    my_public_key_serialised = my_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    ip = "localhost"
    port = 12345

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((ip, port))
    except:
        print("Failed to connect to the server")
        return

    thread_receive = threading.Thread(target=receive_messages, args=(client_socket,my_public_key_serialised))
    thread_receive.start()

    thread_send = threading.Thread(target=send_messages, args=(client_socket, my_public_key_serialised, ip, port))
    thread_send.start()

if __name__ == "__main__":
    main()
