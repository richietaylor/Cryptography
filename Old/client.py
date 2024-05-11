import socket
import threading
import sys
import os

def send(conn, data, is_text=True):
    """ Send data with a header indicating if it's text or binary """
    header = 'TEXT' if is_text else 'FILE'
    conn.send(header.encode('utf-8') + data)

def handle_incoming_messages(conn):
    while True:
        try:
            header = conn.recv(4).decode('utf-8')
            if header == 'TEXT':
                handle_text(conn)
            elif header == 'FILE':
                handle_file(conn)
            else:
                raise ValueError("Unknown data type received")
        except Exception as e:
            print(f"Connection lost: {e}")
            break

def handle_text(conn):
    length = int(conn.recv(10).decode('utf-8').strip())
    data = conn.recv(length).decode('utf-8')
    print(f"Received: {data}")

def handle_file(conn):
    filename = conn.recv(100).decode('utf-8').strip()
    length = int(conn.recv(10).decode('utf-8').strip())
    with open(filename, 'wb') as f:
        while length > 0:
            chunk = conn.recv(min(1024, length))
            if not chunk:
                break
            f.write(chunk)
            length -= len(chunk)
    print(f"Received file: {filename}")

def send_messages(conn):
    while True:
        message = input("Enter message or file path (file:<path>): ")
        if message.startswith("file:"):
            filepath = message[5:]
            try:
                with open(filepath, 'rb') as file:
                    data = file.read()
                    send(conn, f"{os.path.basename(filepath):<100}".encode('utf-8') + f"{len(data):<10}".encode('utf-8') + data, is_text=False)
                    print("File sent successfully.")
            except Exception as e:
                print(f"Failed to send file: {e}")
        else:
            data = f"{len(message):<10}".encode('utf-8') + message.encode('utf-8')
            send(conn, data)


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
        print("Usage: python client.py ip port [server]")
        sys.exit(1)
    ip = sys.argv[1]
    port = int(sys.argv[2])
    act_as_server = len(sys.argv) == 4 and sys.argv[3] == 'server'
    main(ip, port, act_as_server)