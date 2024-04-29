import socket
import threading
import sys

def receive_messages(sock):
    while True:
        try:
            message = sock.recv(1024).decode('utf-8')
            if message:
                print(f"\nReceived: {message}\nType your message: ", end='')
            else:
                raise Exception("Socket closed")
        except Exception as e:
            print(f"\nAn error occurred: {str(e)}")
            print("Disconnected from chat.")
            sock.close()
            break

def send_messages(sock):
    while True:
        message = input("Type your message: ")
        if message.lower() == 'exit':
            sock.close()
            print("Connection closed.")
            break
        try:
            sock.send(message.encode('utf-8'))
        except:
            print("\nUnable to send the message. Connection might be lost.")
            sock.close()
            break

def setup_connection(host, port):
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection.connect((host, port))
        print("Connected to a friend!")
        return connection, True
    except socket.error:
        print("No friend available, waiting for one...")
        try:
            connection.bind((host, port))
            connection.listen(1)
            conn, addr = connection.accept()
            print(f"Connected by {addr}")
            return conn, False
        except Exception as e:
            print(f"Failed to bind or listen on {host}:{port} due to {e}")
            sys.exit()

def start_chat(host='localhost', port=12345):
    conn, started_as_client = setup_connection(host, port)
    thread_receive = threading.Thread(target=receive_messages, args=(conn,))
    thread_send = threading.Thread(target=send_messages, args=(conn,))
    thread_receive.start()
    thread_send.start()
    thread_receive.join()
    thread_send.join()

if __name__ == "__main__":
    host_input = input("Enter host IP (default 'localhost'): ").strip() or 'localhost'
    port_input = input("Enter port number (default 12345): ").strip()
    port_input = int(port_input) if port_input.isdigit() else 12345
    start_chat(host=host_input, port=port_input)
