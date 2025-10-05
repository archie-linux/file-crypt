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
        raise FileNotFoundError(f"Salt file {salt_file} not found.")
    with open(salt_file, 'rb') as f:
        salt = f.read()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def load_key(key_file='secret.key'):
    """Load the key from a file."""
    if not os.path.exists(key_file):
        raise FileNotFoundError("Key file not found. Ensure the key file exists.")
    with open(key_file, 'rb') as f:
        return f.read()

def compute_hash(data):
    """Compute SHA-256 hash of data."""
    return hashlib.sha256(data).hexdigest()

def decrypt_file(input_file, output_file, key, verify_hash=False, decompress=False, force=False, backup=False, verbose=False):
    """Decrypt a file with optional hash verification, decompression, overwrite protection, and backup."""
    if os.path.exists(output_file) and not force:
        response = input(f"Output file {output_file} exists. Overwrite? (y/n): ")
        if response.lower() != 'y':
            print(f"Skipping {output_file}")
            return
    if backup:
        if os.path.exists(input_file):
            shutil.copy(input_file, input_file + '.bak')
            if verbose:
                print(f"Backup created: {input_file}.bak")
    
    fernet = Fernet(key)
    file_size = os.path.getsize(input_file)
    with open(input_file, 'rb') as f, tqdm(total=file_size, unit='B', unit_scale=True, desc="Decrypting") as pbar:
        encrypted_data = f.read()
        pbar.update(len(encrypted_data))
    
    decrypted_data = fernet.decrypt(encrypted_data)
    if decompress:
        decrypted_data = zlib.decompress(decrypted_data)
        if verbose:
            print(f"Decompressed {input_file} after decryption")
    
    if verify_hash:
        hash_file = input_file + '.hash'
        if not os.path.exists(hash_file):
            print(f"Warning: Hash file {hash_file} not found. Skipping verification.")
        else:
            with open(hash_file, 'r') as f:
                expected_hash = f.read().strip()
            computed_hash = compute_hash(decrypted_data)
            if computed_hash != expected_hash:
                raise ValueError(f"Hash verification failed for {input_file}. File may be corrupted or tampered.")
            if verbose:
                print(f"Hash verification passed for {input_file}")
    
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)
    print(f"File decrypted successfully: {output_file}")

def decrypt_multiple_files(input_paths, output_dir, key, verify_hash, decompress, force, backup, verbose):
    """Decrypt multiple files or a directory."""
    os.makedirs(output_dir, exist_ok=True)
    files_to_decrypt = []
    for path in input_paths:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    if file.endswith('.encrypted'):
                        files_to_decrypt.append(os.path.join(root, file))
        elif os.path.isfile(path):
            files_to_decrypt.append(path)
        else:
            print(f"Warning: {path} is not a file or directory.")
    
    for input_file in files_to_decrypt:
        relative_path = os.path.relpath(input_file, os.path.dirname(input_paths[0]))
        output_file = os.path.join(output_dir, relative_path.replace('.encrypted', ''))
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        decrypt_file(input_file, output_file, key, verify_hash, decompress, force, backup, verbose)

def load_config(config_file):
    """Load default arguments from a config file."""
    config = configparser.ConfigParser()
    config.read(config_file)
    return {
        'input': config.get('DEFAULT', 'input', fallback=None),
        'output': config.get('DEFAULT', 'output', fallback=None),
        'key': config.get('DEFAULT', 'key', fallback=None),
        'verify_hash': config.getboolean('DEFAULT', 'verify_hash', fallback=False),
        'decompress': config.getboolean('DEFAULT', 'decompress', fallback=False),
        'force': config.getboolean('DEFAULT', 'force', fallback=False),
        'backup': config.getboolean('DEFAULT', 'backup', fallback=False),
        'verbose': config.getboolean('DEFAULT', 'verbose', fallback=False)
    }

def main():
    """Main function for file decryption with command-line arguments."""
    parser = argparse.ArgumentParser(description="Decrypt a file or directory using Fernet encryption.")
    parser.add_argument('-i', '--input', nargs='+', help="Input encrypted file(s) or directory")
    parser.add_argument('-o', '--output', help="Output directory or file for decrypted data")
    parser.add_argument('-k', '--key', help="Key file containing the encryption key")
    parser.add_argument('--password', help="Password to derive the encryption key")
    parser.add_argument('--verify-hash', action='store_true', help="Verify file integrity using hash")
    parser.add_argument('--decompress', action='store_true', help="Decompress files after decryption")
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
    verify_hash = args.verify_hash or config.get('verify_hash', False)
    decompress = args.decompress or config.get('decompress', False)
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
            if args.key:
                print("Warning: --key is ignored when --password is provided.")
            key = derive_key(args.password)
            if verbose:
                print("Key derived from password.")
        else:
            if not key_file:
                print("Error: --key is required when --password is not provided.")
                sys.exit(1)
            key = load_key(key_file)
            if verbose:
                print(f"Key loaded from {key_file}")

        # Process files
        decrypt_multiple_files(input_paths, output_path, key, verify_hash, decompress, force, backup, verbose)

    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
