import socket
import threading
import sys
import os

def handle_incoming_messages(conn):
    while True:
        try:
            data = conn.recv(1024)
            if not data:
                raise Exception("Connection closed by the remote host.")
            if data.startswith(b'file:'):
                filename = data[5:].decode('utf-8')
                receive_file(conn, filename)
            else:
                print(f"Received: {data.decode('utf-8')}")
        except Exception as e:
            print(f"Connection lost: {e}")
            break

def send_messages(conn):
    try:
        while True:
            message = input("Enter message or file path (file:<path>): ")
            if message.startswith("file:"):
                filepath = message[5:]
                send_file(conn, filepath)
            else:
                conn.send(message.encode('utf-8'))
    except Exception as e:
        print(f"Error sending message: {e}")
        conn.close()

def send_file(conn, filepath):
    if not os.path.isfile(filepath):
        print("File does not exist.")
        return
    conn.send(f"file:{os.path.basename(filepath)}".encode('utf-8'))
    with open(filepath, 'rb') as file:
        while True:
            bytes_read = file.read(1024)
            if not bytes_read:
                break
            conn.send(bytes_read)
    print("File sent successfully.")

def receive_file(conn, filename):
    with open(filename, 'wb') as file:
        while True:
            bytes_data = conn.recv(1024)
            if not bytes_data:
                break
            file.write(bytes_data)
    print(f"Received file: {filename}")

def establish_connection(ip, port):
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection.connect((ip, port))
        print(f"Connected to {ip} on port {port}")
        return connection
    except Exception as e:
        print(f"Could not connect to {ip} on port {port}: {e}")
        return None

def start_server(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))
    server.listen(1)
    print("Waiting for a connection...")
    conn, addr = server.accept()
    print(f"Connected by {addr}")
    return conn

def main(ip, port, act_as_server=False):
    conn = None
    if act_as_server:
        conn = start_server(port)
    else:
        while conn is None:
            conn = establish_connection(ip, port)

    threading.Thread(target=handle_incoming_messages, args=(conn,), daemon=True).start()
    send_messages(conn)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python p2p_messaging.py ip port [server]")
        sys.exit(1)
    ip = sys.argv[1]
    port = int(sys.argv[2])
    act_as_server = len(sys.argv) == 4 and sys.argv[3] == 'server'
    main(ip, port, act_as_server)
