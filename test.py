import socket
import threading

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
    choice = input("Do you want to host (H) or join (J)? ").upper()
    host = 'localhost'
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
        print("Connected to the host.")

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
