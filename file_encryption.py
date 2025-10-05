from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import sys
import argparse
import base64
import zlib
import hashlib
import shutil
import configparser
from tqdm import tqdm
import glob

def derive_key(password, salt_file='salt.bin'):
    """Derive a key from a password using PBKDF2HMAC."""
    if not os.path.exists(salt_file):
        salt = os.urandom(16)
        with open(salt_file, 'wb') as f:
            f.write(salt)
    else:
        with open(salt_file, 'rb') as f:
            salt = f.read()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

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

def compute_hash(data):
    """Compute SHA-256 hash of data."""
    return hashlib.sha256(data).hexdigest()

def encrypt_file(input_file, output_file, key, compress=False, force=False, backup=False, verbose=False):
    """Encrypt a file with optional compression, overwrite protection, and backup."""
    if os.path.exists(output_file) and not force:
        response = input(f"Output file {output_file} exists. Overwrite? (y/n): ")
        if response.lower() != 'y':
            print(f"Skipping {output_file}")
            return
    if backup:
        shutil.copy(input_file, input_file + '.bak')
        if verbose:
            print(f"Backup created: {input_file}.bak")
    
    fernet = Fernet(key)
    file_size = os.path.getsize(input_file)
    with open(input_file, 'rb') as f, tqdm(total=file_size, unit='B', unit_scale=True, desc="Encrypting") as pbar:
        data = f.read()
        pbar.update(len(data))
    
    original_hash = compute_hash(data)
    if compress:
        data = zlib.compress(data)
        if verbose:
            print(f"Compressed {input_file} before encryption")
    
    encrypted_data = fernet.encrypt(data)
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)
    with open(output_file + '.hash', 'w') as f:
        f.write(original_hash)
    if verbose:
        print(f"Hash saved: {output_file}.hash")
    print(f"File encrypted successfully: {output_file}")

def encrypt_multiple_files(input_paths, output_dir, key, compress, force, backup, verbose):
    """Encrypt multiple files or a directory."""
    os.makedirs(output_dir, exist_ok=True)
    files_to_encrypt = []
    for path in input_paths:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    files_to_encrypt.append(os.path.join(root, file))
        elif os.path.isfile(path):
            files_to_encrypt.append(path)
        else:
            print(f"Warning: {path} is not a file or directory.")
    
    for input_file in files_to_encrypt:
        relative_path = os.path.relpath(input_file, os.path.dirname(input_paths[0]))
        output_file = os.path.join(output_dir, relative_path + '.encrypted')
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        encrypt_file(input_file, output_file, key, compress, force, backup, verbose)

def rotate_key(input_file, output_file, old_key, new_key, compress, force, backup, verbose):
    """Decrypt with old key and re-encrypt with new key."""
    temp_file = "temp_decrypted.txt"
    fernet_old = Fernet(old_key)
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = fernet_old.decrypt(encrypted_data)
    with open(temp_file, 'wb') as f:
        f.write(decrypted_data)
    
    encrypt_file(temp_file, output_file, new_key, compress, force, backup, verbose)
    os.remove(temp_file)
    if verbose:
        print("Key rotation completed.")

def load_config(config_file):
    """Load default arguments from a config file."""
    config = configparser.ConfigParser()
    config.read(config_file)
    return {
        'input': config.get('DEFAULT', 'input', fallback=None),
        'output': config.get('DEFAULT', 'output', fallback=None),
        'key': config.get('DEFAULT', 'key', fallback=None),
        'compress': config.getboolean('DEFAULT', 'compress', fallback=False),
        'force': config.getboolean('DEFAULT', 'force', fallback=False),
        'backup': config.getboolean('DEFAULT', 'backup', fallback=False),
        'verbose': config.getboolean('DEFAULT', 'verbose', fallback=False)
    }

def main():
    """Main function to handle encryption with command-line arguments."""
    parser = argparse.ArgumentParser(description="Encrypt a file or directory using Fernet encryption.")
    parser.add_argument('-i', '--input', nargs='+', help="Input file(s) or directory to encrypt")
    parser.add_argument('-o', '--output', help="Output directory or file for encrypted data")
    parser.add_argument('-k', '--key', help="Key file to store/load the encryption key")
    parser.add_argument('--password', help="Password to derive the encryption key")
    parser.add_argument('--rotate-key', help="Old key file for key rotation")
    parser.add_argument('--new-key', help="New key file for key rotation")
    parser.add_argument('--compress', action='store_true', help="Compress files before encryption")
    parser.add_argument('--force', action='store_true', help="Force overwrite of existing output files")
    parser.add_argument('--backup', action='store_true', help="Create backup of input files")
    parser.add_argument('--verbose', action='store_true', help="Enable verbose output")
    parser.add_argument('--config', help="Path to configuration file (INI format)")

    args = parser.parse_args()

    # Show help and exit if no arguments or -h is provided
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    # Load defaults from config file if provided
    config = load_config(args.config) if args.config else {}

    # Apply command-line arguments, falling back to config
    input_paths = args.input or config.get('input', '').split()
    output_path = args.output or config.get('output')
    key_file = args.key or config.get('key')
    compress = args.compress or config.get('compress', False)
    force = args.force or config.get('force', False)
    backup = args.backup or config.get('backup', False)
    verbose = args.verbose or config.get('verbose', False)

    # Validate required arguments
    if not input_paths:
        print("Error: --input is required.")
        parser.print_help()
        sys.exit(1)
    if not output_path:
        print("Error: --output is required.")
        parser.print_help()
        sys.exit(1)

    try:
        # Handle key derivation or loading
        if args.password:
            if args.key or args.rotate_key or args.new_key:
                print("Warning: --key, --rotate-key, and --new-key are ignored when --password is provided.")
            key = derive_key(args.password)
            if verbose:
                print("Key derived from password.")
        elif args.rotate_key:
            if not args.new_key:
                print("Error: --new-key is required for key rotation.")
                sys.exit(1)
            old_key = load_key(args.rotate_key)
            new_key = generate_key(args.new_key) if not os.path.exists(args.new_key) else load_key(args.new_key)
            if verbose:
                print(f"Old key loaded from {args.rotate_key}")
                print(f"New key loaded/generated at {args.new_key}")
        else:
            if not key_file:
                print("Error: --key is required when --password or --rotate-key is not provided.")
                sys.exit(1)
            key = generate_key(key_file) if not os.path.exists(key_file) else load_key(key_file)
            if verbose:
                print(f"Key {'generated and saved to' if not os.path.exists(key_file) else 'loaded from'} {key_file}")

        # Process files
        if args.rotate_key:
            if len(input_paths) > 1 or os.path.isdir(input_paths[0]):
                print("Error: Key rotation supports only a single file.")
                sys.exit(1)
            rotate_key(input_paths[0], output_path, old_key, new_key, compress, force, backup, verbose)
        else:
            encrypt_multiple_files(input_paths, output_path, key, compress, force, backup, verbose)

    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
