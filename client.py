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
    while True:
        if input("S for server or C for client: ") == 'S':    
            server_ip = '127.0.0.1'
            server_port = 12345
            try:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((server_ip, server_port))
            except:
                print("The server is down")
                continue
                
        else:
            ip = "localhost"
            port = 3000
            try:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((ip, port))
            except:
                print("This client is offline")
                continue
                

        thread_receive = threading.Thread(target=receive_messages, args=(client_socket,))
        thread_receive.start()

        thread_send = threading.Thread(target=send_messages, args=(client_socket,))
        thread_send.start()

if __name__ == "__main__":
    main()



