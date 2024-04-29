import socket
import threading

def client_handler(connection, address, clients):
    while True:
        try:
            message = connection.recv(1024).decode('utf-8')
            if message:
                print(f"Received from {address}: {message}")
                broadcast(f"{address} says: {message}", clients)
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
    
    clients = []

    print(f"Server is listening on {host}:{port}")

    while True:
        connection, address = server_socket.accept()
        print(f"Connected with {address}")
        clients.append(connection)
        
        thread = threading.Thread(target=client_handler, args=(connection, address, clients))
        thread.start()

if __name__ == "__main__":
    main()

# import socket
# import threading

# def client_handler(connection, address, clients):
#     while True:
#         try:
#             message = connection.recv(1024).decode('utf-8')
#             if message:
#                 print(f"{address} says: {message}")
#                 broadcast(message, connection, clients)
#             else:
#                 remove_connection(connection, clients)
#                 break
#         except:
#             remove_connection(connection, clients)
#             break

# def broadcast(message, connection, clients):
#     for client in clients:
#         if client != connection:
#             try:
#                 client.send(message.encode('utf-8'))
#             except:
#                 remove_connection(client, clients)

# def remove_connection(connection, clients):
#     if connection in clients:
#         clients.remove(connection)

# def main():
#     host = 'localhost'
#     port = 3000
#     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server_socket.bind((host, port))
#     server_socket.listen()
    
#     clients = []

#     print(f"Server is listening on {host}:{port}")

#     while True:
#         connection, address = server_socket.accept()
#         print(f"Connected with {address}")

#         clients.append(connection)
        
#         thread = threading.Thread(target=client_handler, args=(connection, address, clients))
#         thread.start()

# if __name__ == "__main__":
#     main()
