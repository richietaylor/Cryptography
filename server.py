import socket
import json
import threading
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import dh, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import socket

def client_handler(connection, address, clients):
    while True:
        try:
            message = connection.recv(1024).decode('utf-8')
            if message:
                print(f"Received from {address}: {message}")
                # broadcast(f"{address} says: {message}", clients)
            else:
                remove_connection(connection, clients)
                break
        except:
            remove_connection(connection, clients)
            break

def broadcast(message, clients):
    for client in clients:
        try:
            client.send(message.encode('utf-8'))
        except:
            remove_connection(client, clients)


def remove_connection(connection, clients):
    if connection in clients:
        clients.remove(connection)
        connection.close()
        print(f"Connection closed with {connection}")

def main():
    host = '127.0.0.1'
    port = 12345
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()
    
    # Generate the keys for the certificate
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=512,
    ) 
    public_key = private_key.public_key()
    # Need to serialise the public key before we can send it.
    public_key_serialised =  public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    private_key_serialised =  private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Print for debugging
    print("-----Generated CA's keys-----")
    print(private_key_serialised.decode())
    print(public_key_serialised.decode())
    # Generate the parametes that will be for the Diffie-Hellman algorithm, send these to the clients
    parameters = dh.generate_parameters(generator=2, key_size=512)
    # Extracting the parameters
    p = parameters.parameter_numbers().p
    g = parameters.parameter_numbers().g
    print("-----Generated Parameters for Diffie-Hellman-----")
    print("p:", p)
    print("g:", g)

    # Generate

    clients = []

    print(f"Server is listening on {host}:{port}")

    while True:
        connection, address = server_socket.accept()
        print(f"Connected with {address}")
        clients.append(connection)
        
        thread = threading.Thread(target=client_handler, args=(connection, address, clients))
        thread.start()


        message = input("Message: ")
        broadcast(f"Server says: {message}", clients)

if __name__ == "__main__":
    main()
