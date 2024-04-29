# Client prototype for NIS assignment
# Stephan Maree
# 29/04/2024

import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization

HOST = "127.0.0.1" # localhost
PORT = 25252

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=512,
)
pem = private_key.private_bytes( 
   encoding=serialization.Encoding.PEM,
   format=serialization.PrivateFormat.TraditionalOpenSSL,
   encryption_algorithm=serialization.NoEncryption()
)
print(pem)
public_key = private_key.public_key()
pem = public_key.public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print(pem)

# Bob and Alice need to be able to act as both client and server
choice = input("Are you client (c) or server (s)? ")
if choice == "s":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print("Waiting for connection...")
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            while True:
                data = conn.recv(1024).decode("utf-8")
                if not data:
                    break
                print(f"Server Received {data!r}")
                conn.sendall(b"received!")
else:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        message = input("send: ")
        s.sendall(bytes(message, "utf-8"))
        data = s.recv(1024).decode("utf-8")
        print(f"Client Received {data!r}")