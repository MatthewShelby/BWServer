# BWServer - Blockchain Node.js Server Application

BWServer is a Node.js server application designed to handle user activities and interactions with the blockchain in a blockchain project. It provides functionalities such as user registration, authentication, and Bitcoin transactions. Please note that this project is currently under development and testing.

## Table of Contents

- [Introduction](#introduction)
- [Installation and Setup](#installation-and-setup)
- [Environment Variables](#environment-variables)
- [CORS Policy](#cors-policy)
- [Blockchain Functions](#blockchain-functions)
- [Server Functions](#server-functions)
- [Cryptography](#cryptography)
- [Database Connection](#database-connection)
- [Running the Server](#running-the-server)
- [Contact](#contact)
- [License](#license)

## Introduction

BWServer is a backend component that facilitates communication between the user interface (UI) and the Bitcoin blockchain. It enables user registration, login authentication, and transaction creation in a blockchain project.

## Installation and Setup

1. Clone the repository.
2. Install Node.js and npm if not already installed.
3. Run `npm install` to install the required dependencies.
4. Configure environment variables in a `.env` file.
5. Start the server using `npm start`.

## Environment Variables

The application relies on the following environment variables:

- `PORT`: The port on which the server will run (default is 3001).
- `dburi`: URI for the MongoDB database.
- `aAurl`: An array of accepted URLs for CORS policy.
- ... (other environment variables are used for various purposes in the application)

## CORS Policy

The server enforces a Cross-Origin Resource Sharing (CORS) policy to allow requests from specific origins defined in the `aAurl` environment variable.

## Blockchain Functions

The application includes functions for interacting with the Bitcoin blockchain:

- `setupAccount(pathIndex, mainPrivateKey)`: Sets up a Bitcoin account based on a given path index and main private key.
- `fetchData(senderAddress, destinationAddress, txAmount, periority, gassAmount)`: Fetches data related to transactions and unspent outputs for a new transaction.
- ... (other functions related to transaction creation and blockchain interaction)

## Server Functions

The server functions handle various routes and actions in the application, including:

- `/register`: Registers a new user and generates a Bitcoin account for them.
- `/login`: Manages user login authentication and session management.
- `/transfer`: Initiates Bitcoin transfers between addresses.
- `/health`: Endpoint for checking server availability.
- `/status`: Checks the status of the database connection.
- `/fees`: Fetches current fee rates for Bitcoin transactions.

## Cryptography

AES-256-CBC encryption is used to securely store sensitive data. Encryption and decryption functions protect user data, such as passwords.

## Database Connection

The `dbConnect` function ensures a reliable connection to the MongoDB database.

## Running the Server

Start the server using `npm start`. The server will listen on the port specified in the environment variable or default to port 3001.

## Contact

For inquiries, feedback, or collaboration, please contact Matthew Sheldon at matthewShelB@gmail.com.

## License

This project is developed under no license. It is currently under development and testing phase.
