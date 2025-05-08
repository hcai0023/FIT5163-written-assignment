# Diffie-Hellman Key Exchange and OPAQUE Protocol Implementation

## Introduction

This project implements the Diffie-Hellman key exchange protocol and extends it to the OPAQUE (Oblivious Password Authentication and Key Exchange) protocol. It provides a secure way for two parties to establish a shared secret key over an insecure channel and demonstrates resistance to man-in-the-middle attacks and offline password dictionary attacks.

## Features

- **Diffie-Hellman Key Exchange**: Enables two parties to securely establish a shared secret key over an insecure channel.
- **OPAQUE Protocol**: Extends the Diffie-Hellman protocol to provide resistance against offline password dictionary attacks.
- **Graphical User Interface (GUI)**: Provides an interactive interface for demonstrating the protocols and their security features.
- **Security Demonstrations**: Includes simulations of man-in-the-middle attacks and offline password dictionary attacks to showcase the protocols' security.

## Technical Implementation

### Diffie-Hellman Class

Implements the core Diffie-Hellman key exchange functionality, including:

- Key generation
- Shared key computation
- Public key signing and verification using RSA signatures

### OPAQUE Protocol

Implements the following components of the OPAQUE protocol:

- Blinding and unblinding operations
- Envelope construction and opening
- Interaction between the server and client

### GUI Design

Utilizes tkinter to create a user-friendly interface with two tabs:

- **Diffie-Hellman Tab**: Allows users to input parameters, generate keys and shared keys, and simulate man-in-the-middle attacks.
- **OPAQUE Tab**: Enables user registration and login, and demonstrates secure channel shared key establishment and resistance to offline password dictionary attacks.

## Security Analysis

### Diffie-Hellman Security

- Relies on the computational difficulty of the discrete logarithm problem.
- Ensures security by choosing a sufficiently large prime p and an appropriate primitive root g.

### OPAQUE Protocol Security

- Combines password hashes with key exchange to protect against offline attacks.
- Uses local file storage to eliminate server involvement and reduce communication-related security risks.

### Attack Simulations

- Demonstrates the vulnerability of the Diffie-Hellman protocol to man-in-the-middle attacks if not properly secured.
- Shows the OPAQUE protocol's resistance to offline password dictionary attacks when strong passwords are used.

## Usage

### Prerequisites

- Python 3.x
- Required libraries: pycryptodome, tkinter

### Running the Code

1. Clone the repository or download the DH-OPAQUE.py file.
2. Install the required libraries using pip: `pip install pycryptodome`
3. Execute the DH-OPAQUE.py file to launch the GUI application.

### Getting Started

- **Diffie-Hellman Tab**: Enter the prime p and generator g values in the respective fields. Click the "Generate Keys and Shared Key" button to generate public keys and shared keys for Alice and Bob. Use the "Simulate Man-in-the-Middle Attack" button to demonstrate the attack.
- **OPAQUE Tab**: Register users by entering a username and password and clicking the "Register" button. Perform logins using registered credentials and click the "Login" button. Use the buttons to demonstrate secure channel shared key establishment and resistance to offline password dictionary attacks.

## Team Work and Acknowledgments

This group assignment was a challenging but rewarding experience. The team members collaborated closely, leveraging their diverse skills and knowledge to overcome the difficulties posed by the complex cryptographic concepts and tight timeline. We would like to express our sincere gratitude to the course instructor and teaching assistants for their valuable guidance and support throughout the project.

## Note

This code is provided for educational purposes to demonstrate the implementation of cryptographic protocols. It should not be used in production systems without further security review and enhancements.
