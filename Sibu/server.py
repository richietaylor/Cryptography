import socket
import os
import json
import concurrent.futures as thread_pool

SERVER_HOST = 'localhost'
SERVER_PORT = 12000
BLOCK_SIZE = 1024           # Block sizes to read from the file at a time
CONNECTIONS = {}

def authenticate_user(connection, username, password):
    """Reads from database to determine if user exists, creates a new entry if they don't."""
    if not os.path.exists("../database"):  # Create a database if it does not exist
        os.makedirs("../database")
    # Create a json file if it does not exist
    if not os.path.exists("../database/users.json"):
        with open("../database/users.json", "w") as f:
            f.write("{}")

    # Flag to determine if the user exists or not
    user_exists = False
    users = {}

    # Reads from a file that has all known users
    # Search for a user with the given username
    with open("../database/users.json", "r") as file:
        users = json.load(file)

        for user in users:
            if user == username:
                user_exists = True
                break

    if not user_exists:  # If it is a new user, they are registered
        return register_user(connection, username, password)

    else:
        if password == users[username]["password"]:
            print(f"Authentication Successful")
            return "Authentication Successful"

        else:
            # Send authentication failed message
            print("Authentication failed because password didn't match")
            return "Authentication Error"


def register_user(connection, username, password):
    """Adds a new user to the record of users"""
    print(username, password)
    # Alert the client that the user is new
    auth_obj = {
        "message_type": "AUTH NEW USER",
    }

    connection.sendall(json.dumps(auth_obj).encode())

    # Add the user to the file
    with open("../database/users.json", "r+") as f:
        users = json.load(f)

        users[username] = {
            "password": password,
        }

        f.seek(0)  # sets the file pointer position to the beginning of the file
        json.dump(users, f, indent=4, separators=(',', ': '))
        f.write('\n')
    return "Authentication Successful"


def list_users(connection):
    """Lists all users that are registered"""
    users = []
    with open("../database/users.json", "r") as file:
        users = json.load(file)

    data = {
        "message_type": "USER LISTING",
        "body": users
    }
    json_object = json.dumps(data)
    connection.sendall(json_object.encode())
    print("File list sent to client")

def user_auth(connection):
    """Handles an incoming client request."""

    AUTHENTICATED = False
    username = ""
    password = ""

    while not AUTHENTICATED:
        # Authenticate the user first
        data = connection.recv(BLOCK_SIZE)
        json_object = data.decode()
        message = json.loads(json_object)

        if message["message_type"] == "AUTH":  # Authentication message
            username = message["username"]
            password = message["password"]

            auth_result = authenticate_user(connection, username, password)

            auth_response = ""
            if auth_result == "Authentication Error":
                print(f"Auth failed")

                # Send an authentication error
                auth_response = {
                    "message_type": "AUTHENTICATION CONFIRMATION",
                    "result": "no"
                }
            elif auth_result == "Authentication Successful":
                AUTHENTICATED = True

                auth_response = {
                    "message_type": "AUTHENTICATION CONFIRMATION",
                    "result": "yes"
                }
                CONNECTIONS[username] = connection

            json_data = json.dumps(auth_response)
            connection.sendall(json_data.encode())
    handle_requests(connection, username)
    return

def handle_requests(connection, username):
    """Handles incoming client requests."""
    # Command input loop
    while True:
        print(f"Waiting for command...")
        try:
            connection.getpeername()  # Checks if the connection still open, if not, kill the thread

            # Get next message
            data = connection.recv(BLOCK_SIZE)

            json_object = data.decode().strip()
            message = json.loads(json_object)
            message_type = message["message_type"]
            print(f"Command Received: {message_type}")

            if message_type == "LIST":
                list_users(connection)

            elif message_type == "MESSAGE":
                relay_message(connection, data, message['user'])

            elif message_type == "QUIT":
                print(f"User \"{username}\" disconnected")
                connection.close()
                break

        except (BrokenPipeError, ConnectionResetError):
            print(f'Error: Connection lost')
            break
    return

# A function that relays a message from one client to another without decrypting it
def relay_message(connectionFrom, data, user):
    """Relays a message from one client to another."""
    connectionTo = CONNECTIONS[user]
    connectionTo.sendall(data)
    return

def listen_for_exit_command():
    """Listen for 'exit' command from the console to stop the server."""
    while True:
        user_input = input("Type 'exit' to stop the server:\n")
        if user_input.lower() == 'exit':
            print("Stopping server...")
            for connection in CONNECTIONS:
                CONNECTIONS[connection].close()
            os._exit(0)
    

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clientSocket:
        clientSocket.bind((SERVER_HOST, SERVER_PORT))
        clientSocket.listen(10)

        print(f'Server listening on {SERVER_HOST}: {SERVER_PORT}...')

        # Create a thread pool with 5 threads
        pool = thread_pool.ThreadPoolExecutor(max_workers=5)
        
        pool.submit(listen_for_exit_command)

        while True:
            connection, address = clientSocket.accept()

            print(f'Client connected from {address[0]} :{address[1]}')
            # Assigning a new connection to a thread
            pool.submit(user_auth, connection)

if __name__ == '__main__':
    main()
