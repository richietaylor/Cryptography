import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization


def print_keys(private,public):
    # This method only exists to make main method more readable
    private_serialisation = private.private_bytes( 
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    print(private_serialisation)
    public_serialisation = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(public_serialisation)

def receive_messages(sock):
    while True:
        try:
            message = sock.recv(1024).decode('utf-8')
            if message:
                print("Received:", message)
            else:
                break
        except:
            print("Connection closed.")
            break

def send_messages(sock):
    while True:
        message = input("Send: ")
        sock.send(message.encode('utf-8'))

def main():
    # Generate Private Key for RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537, # This is the standard number that all applications should use
        key_size=512,
    )
    public_key = private_key.public_key() # Get the associated public key

    # print for debugging
    print_keys(private_key,public_key)
    

    choice = input("Do you want to host (H) or join (J)? ").upper()
    host = '196.24.139.141'
    port = 12345

    if choice == 'H':
        # Setting up as host
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((host, port))
        server.listen(1)
        print("Waiting for connection...")
        connection, address = server.accept()
        print("Connected to", address)
    else:
        # Setting up as client
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.connect((host, port))
        print("Connected")

    # Start receiving and sending messages
    receive_thread = threading.Thread(target=receive_messages, args=(connection,))
    receive_thread.start()

    send_thread = threading.Thread(target=send_messages, args=(connection,))
    send_thread.start()

    receive_thread.join()
    send_thread.join()

    connection.close()

if __name__ == "__main__":
    main()
