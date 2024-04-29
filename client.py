import socket
import threading

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

def send_messages(sock):
    while True:
        message = input("Message: ")
        try:
            sock.send(message.encode('utf-8'))
        except:
            print("Failed to send message")
            sock.close()
            break

def main():
    host = '127.0.0.1'
    port = 12345
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((host, port))
    except:
        print("The server is down")
    
    thread_receive = threading.Thread(target=receive_messages, args=(client_socket,))
    thread_receive.start()

    thread_send = threading.Thread(target=send_messages, args=(client_socket,))
    thread_send.start()

if __name__ == "__main__":
    main()



