import socket

def main():
    host = 'localhost'
    port = 3000
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    
    while True:
        message = input("Message: ")
        client_socket.send(message.encode('utf-8'))
        # Receiving the broadcast message from the server
        server_message = client_socket.recv(1024).decode('utf-8')
        print(f"From server: {server_message}")

if __name__ == "__main__":
    main()
