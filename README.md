# Symmetric Key Distribution Using RSA

## Project Overview

This project implements a secure communication system using a **hybrid encryption approach**:

*  **RSA (Asymmetric Encryption)** → used to securely exchange a symmetric key
*  **Symmetric Encryption** → used to encrypt and decrypt messages

The system follows a **client-server model**, where the server acts as a trusted authority that distributes encrypted symmetric keys to clients.

---

## Objectives

* Understand how **RSA** is used for secure key exchange
* Learn how **symmetric encryption** works in real communication
* Simulate a secure client-server communication system
* Apply best practices in cryptography and software structure

---

## Technologies Used

* Python 3
* `cryptography` library (for RSA & symmetric encryption)
* Sockets (for client-server communication)

---

## Project Structure

```
symmetric-key-distribution-rsa/
│
├── server/        # Server logic (key distribution)
├── client/        # Client logic (request & use key)
├── crypto/        # Encryption utilities (RSA + symmetric)
├── logs/          # Log files
├── tests/         # Unit tests
│
├── README.md
├── requirements.txt
└── .gitignore
```

---

## Installation

1. Clone the repository:

```
git clone https://github.com/Grejonaa/symmetric-key-distribution-rsa.git
cd symmetric-key-distribution-rsa
```

2. Install dependencies:

```
pip install -r requirements.txt
```

---

## How to Run

### Start the server:

```
python server/server.py
```

### Start the client:

```
python client/client.py
```

---

## How It Works

1. Client sends a request to the server
2. Server generates a **symmetric key**
3. Server encrypts the key using **RSA public key**
4. Client decrypts it using **RSA private key**
5. Client and server use the symmetric key for secure communication

---

## Example Workflow

Client:

```
Requesting symmetric key...
Key received and decrypted successfully.
Enter message:
> Hello secure world
```

Server:

```
Client connected...
Encrypted symmetric key sent.
Message received and decrypted successfully.
```

---

## Features

* RSA key exchange
* Symmetric encryption for messages
* Client-server communication
* Logging of key events
* Error handling

---

## Error Handling

The system includes:

* Invalid key handling
* Connection errors
* Encryption/decryption errors

---

## Evaluation Criteria Covered

✔ RSA Implementation
✔ Secure Key Exchange
✔ Clean Code Structure
✔ User-Friendly Console Interface
✔ Logging and Error Handling
✔ Documentation

---

## Educational Note

This project demonstrates a **hybrid encryption model**, which is widely used in real-world systems such as HTTPS, where RSA is used for secure key exchange and symmetric encryption is used for performance.

---

## Author

Grejona Gashi, Gerti Parduzi, Genti Kafexhiu, Elmaze Murati
