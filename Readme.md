# FileCrypt

A Python-based tool for securely encrypting and decrypting files using Fernet symmetric encryption from the `cryptography` library. This project provides simple, secure, and efficient scripts for both encryption and decryption of files.

## Features

- Encrypt files of any type (text, images, etc.) with a secure key.
- Decrypt files using the corresponding key.
- Generates and manages encryption keys securely.
- Robust error handling for file and key operations.

## Prerequisites

- Python 3.6 or higher
- `cryptography` library

## Installation

1. **Clone the Repository** (or download the project files):

- git clone https://github.com/yourusername/file-crypt.git
- cd FileCrypt

2. **Create a Virtual Environment** :

- python -m venv venv
- source venv/bin/activate  # On Windows: venv\Scripts\activate

3. **Install Dependencies**: Install the required cryptography library using pip:

- pip install cryptography

4. **Encrypt File**

- python file_encryption.py
- cat secret.key
- cat example.txt.encrypted

5. **Decrypt File**

- python file_decryption.py
- cat example_decrypted.txt

### Credits: Grok (Done in 5 mins)

P.S. - This is the very first project in the AI-Assisted 5-Minute Projects series. I'm planning to do more of these for a change.

**Note**: To be precise, the project actually got done in 3 minutes, double-checking and proofreading added the extra 2 minutes.
