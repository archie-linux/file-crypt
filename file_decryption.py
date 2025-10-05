from cryptography.fernet import Fernet
import os

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
    """Main function for file decryption."""
    # File paths
    input_file = 'example.txt.encrypted'  # The encrypted file
    output_file = 'example_decrypted.txt'  # The decrypted output file
    key_file = 'secret.key'  # The key file

    try:
        # Load the key
        key = load_key(key_file)
        
        # Decrypt the file
        decrypt_file(input_file, output_file, key)

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
