import os
import threading
import socket
import json
import hashlib

# Constants

SERVER_HOST = "localhost"
SERVER_PORT = 12000
BLOCK_SIZE = 1024           # Block sizes to read from the file at a time

# Globals
USERNAME = ""
terminate_flag = False

def main():
    """"Connecting to the server"""
    connecting = True
    while connecting:
        try:
            clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            clientSocket.connect((SERVER_HOST, SERVER_PORT))
            connecting = False
        except Exception as e:
            print("Error: You are not connected to the server")
    global USERNAME
    global terminate_flag

    isAuthenticated = False

    while not isAuthenticated:
        username = input("Please enter your username:\n>>> ")
        password = input("Please enter your password:\n>>> ")

        # send the username and password to the server
        auth_obj = {
            "message_type": "AUTH",
            "username": username,
            "password": password,
        }

        clientSocket.sendall(json.dumps(auth_obj).encode())

        # receive the response from the server
        response = clientSocket.recv(BLOCK_SIZE).decode()
        auth_info = json.loads(response)

        if auth_info["message_type"] == "AUTH NEW USER":
            print("Welcome " + username)
            isAuthenticated = True

        elif auth_info["message_type"] == "AUTHENTICATION CONFIRMATION":
            if auth_info["result"] == "yes":
                print("Welcome " + username)
                USERNAME = username
                isAuthenticated = True
            else:
                print("Authentication failed. Please try again.\nIf this is your first login, the username may be taken")
                continue

    
    menu(clientSocket)
    clientSocket.close()

def menu(clientSocket):
    while True:
        input("\n-Press RETURN to continue")
        # Uncomment for Linux
        # os.system('clear')
        os.system('cls') 
        print("\nEnter the name of the person you want to send a message to")
        print("\nInput a command number and press RETURN:\n   \
              1 - Enter Chat\n   \
              2 - List all users\n   \
              3 - List Files\n   \
              4 - Delete File\n   \
              5 - Change Directory\n   \
              0 - Quit")
        command = input(">>> ").strip()

        if command == "1":
            # Enter Chat
            print("Enter the user name")
            user = input(">>> ").strip()
            # check with server
            chat(clientSocket, user)
            terminate_flag = False
        elif command == "2":
            # List all users
            userList = []
            # get the list of users from the server
            for user in userList:
                print(user)
        elif command == "3":
            # @TODO List Files
            print("TODO - List Files")
        elif command == "4":
            # @TODO Delete Files
            print("TODO - Delete Files")
        elif command == "5":
            # @TODO Change Dir Files
            print("TODO - Change Dir")

        elif command == "0":
            break
        else:
            print("Invalid command. Please try again.")

    return
  
def chat(serverSocket, user):
    global terminate_flag
    listenThread = threading.Thread(target=receiveMessage, args=(serverSocket,))
    listenThread.start()
    print(user)
    print("Enter 0 to quit the chat.\nEnter 1 to send a file.")
    while True:
        message = input(">>> ")
        if message.isdigit() and eval(message) == 0:
            terminate_flag = True
            break
        if message.isdigit() and eval(message) == 1:
            filepath = input("Please enter the name of the file: ")
            sendFile(serverSocket, message, user)
        else:
            sendMessage(serverSocket, message, user)
    return

def receiveMessage(clientSocket):
    """Receive a message from the server."""
    while not terminate_flag:
        data = clientSocket.recv(BLOCK_SIZE).decode()
        m = json.loads(data)
        # Decrypt message here
        decrypted_message = decrypt_message(m["message"])
        print(f"Message received: {decrypted_message}")
        print(">>> ", end="") # This may need changing...

def sendMessage(serverSocket, message, user):
    """Send a message to the server."""
    # Encrypt message here
    encrypted_message = encrypt_message(message)
    message_obj = {
        "message_type": "MESSAGE",
        "message": encrypted_message,
        "username": USERNAME,
        "user": user,
    }

    serverSocket.sendall(json.dumps(message_obj).encode())
    return

def sendFile(serverSocket, filepath, user):
    # @TODO Send File
    return

def encrypt_message(message):
    """Encrypt the message."""
    return message

def decrypt_message(message):
    """Decrypt the message."""
    return message

if __name__ == '__main__':
    main()
