# Secure Messaging System with Certificate Authority Challenge

## Project Overview

This project implements a secure messaging system with a Certificate Authority (CA) challenge mechanism. The system ensures the confidentiality, integrity, and authenticity of messages exchanged between clients. The CA issues certificates to clients after a challenge-response verification, ensuring that only legitimate clients can obtain certificates.

## Features

- **Secure Communication**: Ensures confidentiality and integrity of messages using encryption and digital signatures.
- **Client Authentication**: Uses certificates issued by the CA to authenticate clients.
- **Certificate Authority Challenge**: Implements a challenge-response mechanism during certificate issuance.
- **Multithreaded Server**: Supports multiple concurrent client connections.
- **File Transfer**: Allows clients to securely transfer files.

## Cryptographic Algorithms

The project uses the following cryptographic algorithms:

- **RSA (Rivest-Shamir-Adleman) Algorithm**: Used for key generation, encryption, and digital signatures.
- **SHA-256 (Secure Hash Algorithm 256-bit)**: Used for hashing data for digital signatures.
- **X.509 Standard**: Defines the format of the certificates issued by the CA.

## Getting Started

### Prerequisites

- Python 3.6 or higher
- `cryptography` library
- `socket`, `json`, `threading`, and other standard Python libraries

### Installation


1. Install the required Python packages:
    ```bash
    pip install cryptography
    ```

### Running the Server

1. Run:
    ```bash
    python server.py
    ```
### Running the Client

1. Runs:
    ```bash
    python client.py
    ```

2. Follow the prompts to authenticate, generate/load keys, request certificates, and communicate with other clients.

## Project Structure


- server.py: Server-side implementation
- client.py: Client-side implementation
- README.md: Project documentation
-  keys.json: Stores generated keys (initially empty)
- ca_private_key.pem: CA's private key (generated)
- ca_public_key.pem: CA's public key (generated)
- database/: Directory for storing user data
      └── users.json: Stores user credentials


## How It Works

### Server-Side

1. The server generates CA keys if they do not exist and listens for client connections.
2. When a client requests a certificate, the server generates a random challenge, encrypts it with the client's public key, and sends it to the client.
3. The client decrypts the challenge and sends it back to the server.
4. If the challenge is verified, the server issues an X.509 certificate signed with the CA's private key.

### Client-Side

1. The client connects to the server and authenticates using a username and password.
2. The client generates or loads its RSA keys and requests a certificate from the server.
3. The client decrypts the challenge sent by the server and responds.
4. If the challenge response is correct, the client receives its certificate.
5. The client can now securely communicate with other clients using the issued certificate.

## Usage

### Commands

- **Enter Chat**: Initiates a chat with another user.
- **List all users**: Lists all registered users.
- **List Files**: Lists files in the current directory.
- **Delete File**: Deletes a specified file.
- **Change Directory**: Changes the current working directory.
- **Quit**: Exits the application.

### Secure Communication

- **Messages**: Encrypted using AES and signed using RSA.
- **Files**: Encrypted and transferred securely between clients.



## Acknowledgments

By Stephan, Sibusiso, and Richard

Thanks for reading :heart: