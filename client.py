import socket
import json
import threading
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization

def receive_messages(sock):
    while True:
        try:
            message = sock.recv(1024).decode('utf-8')
            if message:
                print("\r" + message + "\nMessage: ", end="")
        except:
            print("You have been disconnected from the server")
            sock.close()
            break

def send_messages(sock,my_public_key_serialised,ip,port):
    # First send our public key, IP, and Port Number
    init_message = json.dumps({"public_key":my_public_key_serialised.decode(),"ip":ip,"port":port}).encode()
    try:
        sock.send(init_message)
    except:
        print("Failed to send initial message")
        sock.close()
    while True:
        message = input("Message: ")
        try:
            sock.send(message.encode('utf-8'))
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
    # Need to serialise the public key before we can send it.
    my_public_key_serialised =  my_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    while True:
        # if input("S for server or C for client: ") == 'S':    
        #     server_ip = '127.0.0.1'
        #     server_port = 12345
        #     try:
        #         client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #         client_socket.connect((server_ip, server_port))
        #     except:
        #         print("The server is down")
        #         continue 
        # else:
        ip = "localhost"
        port = 12345
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((ip, port))
        except:
            print("This client is offline")
            continue
                
        thread_receive = threading.Thread(target=receive_messages, args=(client_socket,))
        thread_receive.start()

        thread_send = threading.Thread(target=send_messages, args=(client_socket,my_public_key_serialised,ip,port))
        thread_send.start()

if __name__ == "__main__":
    main()



