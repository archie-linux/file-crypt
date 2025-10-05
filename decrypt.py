import argparse
import sys
from crypto_utils import derive_key, load_key, decrypt_file
from file_utils import collect_files, create_output_path
from config_utils import load_config

def decrypt_multiple_files(input_paths, output_dir, key, verify_hash, decompress, force, backup, verbose):
    """Decrypt multiple files or a directory."""
    files_to_decrypt = collect_files(input_paths, extension_filter='.encrypted')
    for input_file in files_to_decrypt:
        output_file = create_output_path(input_file, output_dir, input_paths[0], suffix='.encrypted')
        decrypt_file(input_file, output_file, key, verify_hash, decompress, force, backup, verbose)

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

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    config = load_config(args.config) if args.config else {}

    input_paths = args.input or config.get('input', '').split()
    output_path = args.output or config.get('output')
    key_file = args.key or config.get('key')
    verify_hash = args.verify_hash or config.get('verify_hash', False)
    decompress = args.decompress or config.get('decompress', False)
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

        decrypt_multiple_files(input_paths, output_path, key, verify_hash, decompress, force, backup, verbose)

    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

