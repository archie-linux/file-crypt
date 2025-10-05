import argparse
import os
import sys
from crypto_utils import derive_key, generate_key, load_key, encrypt_file, rotate_key
from file_utils import collect_files, create_output_path
from config_utils import load_config


def encrypt_multiple_files(input_paths, output_dir, key, compress, force, backup, verbose):
    """Encrypt multiple files or a directory."""
    files_to_encrypt = collect_files(input_paths)
    for input_file in files_to_encrypt:
        output_file = create_output_path(input_file, output_dir, input_paths[0], suffix=None) + '.encrypted'
        encrypt_file(input_file, output_file, key, compress, force, backup, verbose)

def main():
    """Main function for file encryption with command-line arguments."""
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

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    config = load_config(args.config) if args.config else {}

    input_paths = args.input or config.get('input', '').split()
    output_path = args.output or config.get('output')
    key_file = args.key or config.get('key')
    compress = args.compress or config.get('compress', False)
    force = args.force or config.get('force', False)
    backup = args.backup or config.get('backup', False)
    verbose = args.verbose or config.get('verbose', False)

    if not input_paths:
        print("Error: --input is required.")
        parser.print_help()
        sys.exit(1)
    if not output_path:
        print("Error: --output is required.")
        parser.print_help()
        sys.exit(1)

    try:
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

