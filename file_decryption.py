from cryptography.fernet import Fernet
import os
import sys
import argparse

def load_key(key_file='secret.key'):
    """Load the key from a file."""
    if not os.path.exists(key_file):
        raise FileNotFoundError("Key file not found. Ensure the key file exists.")
    with open(key_file, 'rb') as f:
        return f.read()

def decrypt_file(input_file, output_file, key):
    """Decrypt a file using the provided key."""
    fernet = Fernet(key)
    try:
        with open(input_file, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
        print(f"File decrypted successfully: {output_file}")
    except Exception as e:
        print(f"Decryption failed: {e}")

def main():
    """Main function for file decryption with command-line arguments."""
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Decrypt a file using Fernet encryption.")
    parser.add_argument('-i', '--input', help="Input encrypted file")
    parser.add_argument('-o', '--output', help="Output decrypted file")
    parser.add_argument('-k', '--key', help="Key file containing the encryption key")

    # Parse arguments
    args = parser.parse_args()

    # Show help and exit if no arguments
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    input_file = args.input
    output_file = args.output
    key_file = args.key

    try:
        # Check if input file and key file exist
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"Input file {input_file} not found.")
        if not os.path.exists(key_file):
            raise FileNotFoundError(f"Key file {key_file} not found.")

        # Load the key
        key = load_key(key_file)
        print(f"Key loaded from {key_file}")

        # Decrypt the file
        decrypt_file(input_file, output_file, key)

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
