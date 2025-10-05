from cryptography.fernet import Fernet
import os
import sys
import argparse

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
    """Main function to handle encryption with command-line arguments."""
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Encrypt a file using Fernet encryption.")
    parser.add_argument('-i', '--input', help="Input file to encrypt")
    parser.add_argument('-o', '--output', help="Output encrypted file")
    parser.add_argument('-k', '--key', help="Key file to store/load the encryption key")

    # Parse arguments
    args = parser.parse_args()

    # Show help and exit if no arguments
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    input_file = args.input
    encrypted_file = args.output
    key_file = args.key

    try:
        # Generate and save a key if it doesn't exist
        if not os.path.exists(key_file):
            key = generate_key(key_file)
            print(f"Key generated and saved to {key_file}")
        else:
            key = load_key(key_file)
            print(f"Key loaded from {key_file}")

        # Check if input file exists
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"Input file {input_file} not found.")

        # Encrypt the file
        encrypt_file(input_file, encrypted_file, key)

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
