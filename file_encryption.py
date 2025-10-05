# file_encryption.py
from cryptography.fernet import Fernet
import os

def generate_key(key_file='secret.key'):
    """Generate a key and save it to a file."""
    key = Fernet.generate_key()
    with open(key_file, 'wb') as f:
        f.write(key)
    return key

def load_key(key_file='secret.key'):
    """Load the key from a file."""
    if not os.path.exists(key_file):
        raise FileNotFoundError("Key file not found. Generate a key first.")
    with open(key_file, 'rb') as f:
        return f.read()

def encrypt_file(input_file, output_file, key):
    """Encrypt a file using the provided key."""
    fernet = Fernet(key)
    with open(input_file, 'rb') as f:
        data = f.read()
    encrypted_data = fernet.encrypt(data)
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)
    print(f"File encrypted successfully: {output_file}")

def main():
    """Main function to demonstrate encryption."""
    # File paths
    input_file = 'example.txt'
    encrypted_file = 'example.txt.encrypted'
    key_file = 'secret.key'

    # Create a sample file to encrypt
    with open(input_file, 'w') as f:
        f.write("This is a sample text file for encryption.")

    try:
        # Generate and save a key
        key = generate_key(key_file)
        print("Key generated and saved.")

        # Encrypt the file
        encrypt_file(input_file, encrypted_file, key)

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
