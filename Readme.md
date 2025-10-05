# FileCrypt

A Python-based tool for securely encrypting and decrypting files using Fernet symmetric encryption from the `cryptography` library. This project provides simple, secure, and efficient scripts for both encryption and decryption of files, with advanced features for flexibility and security.

## Features

- Encrypt and decrypt files of any type (text, images, etc.) with a secure key.
- Support for password-protected key derivation using PBKDF2HMAC.
- Encrypt/decrypt multiple files or entire directories.
- Overwrite protection to prevent accidental data loss.
- Verbose mode for detailed operation logging.
- Key rotation for updating encryption keys.
- Compression before encryption to reduce file size.
- Progress bar for large file operations.
- File integrity verification using SHA-256 hashes.
- Configuration file support for default settings.
- Backup option to preserve input files.
- Generates and manages encryption keys securely.
- Robust error handling for file and key operations.

## Prerequisites

- Python 3.6 or higher
- `cryptography` library
- `tqdm` library (for progress bar)

## Installation

1. **Clone the Repository** (or download the project files):

   ```bash
   git clone https://github.com/yourusername/file-crypt.git
   cd FileCrypt
   ```

2. **Create a Virtual Environment**:

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:

   Install the required libraries using pip:

   ```bash
   pip install cryptography tqdm
   ```

## Usage

The project includes two scripts: `encrypt.py` for encryption and `decrypt.py` for decryption. Both scripts support a variety of command-line flags to customize behavior. If no arguments are provided or the `-h/--help` flag is used, a help message is displayed.

### Encryption (`encrypt.py`)

Encrypt files or directories using a key file or a password-derived key. Supports multiple files, compression, key rotation, and more.

**Command-Line Flags**:
- `-i/--input`: Input conferencia file(s) or directory to encrypt (required, supports multiple paths).
- `-o/--output`: Output file or directory for encrypted data (required).
- `-k/--key`: Key file to store/load the encryption key (required unless `--password` is used).
- `--password`: Password to derive the encryption key (ignores `--key` if provided).
- `--rotate-key`: Old key file for key rotation (requires `--new-key`, single file only).
- `--new-key`: New key file for key rotation.
- `--compress`: Compress files before encryption to reduce size.
- `--force`: Force overwrite of existing output files without prompting.
- `--backup`: Create a backup of input files (`.bak` extension).
- `--verbose`: Enable detailed output for operations.
- `--config`: Path to an INI configuration file for default settings.
- `-h/--help`: Show the help message and exit.

**Examples**:

1. **Encrypt a Single File with a Key File**:
   ```bash
   python encrypt.py -i example.txt -o example.txt.encrypted -k secret.key --verbose
   ```
   Generates or loads `secret.key`, encrypts `example.txt`, and saves the result to `example.txt.encrypted`.

2. **Encrypt a File with a Password**:
   ```bash
   python encrypt.py -i example.txt -o example.txt.encrypted --password mysecurepassword --compress
   ```
   Derives a key from the password, compresses the file, and encrypts it. Creates `salt.bin` for key derivation.

3. **Encrypt Multiple Files**:
   ```bash
   python encrypt.py -i file1.txt file2.txt -o output_dir -k secret.key --backup
   ```
   Encrypts `file1.txt` and `file2.txt`, saves results to `output_dir/file1.txt.encrypted` and `output_dir/file2.txt.encrypted`, and creates backups.

4. **Encrypt a Directory**:
   ```bash
   python encrypt.py -i input_dir -o output_dir -k secret.key --force --verbose
   ```
   Encrypts all files in `input_dir`, preserving directory structure in `output_dir`.

5. **Key Rotation**:
   ```bash
   python encrypt.py -i old.encrypted -o new.encrypted --rotate-key old_key.key --new-key new_key.key
   ```
   Decrypts `old.encrypted` with `old_key.key` and re-encrypts it with `new_key.key`.

6. **Using a Configuration File**:
   Create `config.ini`:
   ```ini
   [DEFAULT]
   input = example.txt
   output = output_dir
   key = secret.key
   compress = True
   backup = True
   verbose = True
   ```
   Run:
   ```bash
   python encrypt.py --config config.ini
   ```

7. **Show Help**:
   ```bash
   python encrypt.py -h
   ```

### Decryption (`decrypt.py`)

Decrypt files or directories using the same key or password used for encryption. Supports hash verification, decompression, and more.

**Command-Line Flags**:
- `-i/--input`: Input encrypted file(s) or directory (required, supports multiple paths).
- `-o/--output`: Output file or directory for decrypted data (required).
- `-k/--key`: Key file containing the encryption key (required unless `--password` is used).
- `--password`: Password to derive the encryption key (ignores `--key` if provided).
- `--verify-hash`: Verify file integrity using the stored SHA-256 hash.
- `--decompress`: Decompress files after decryption (required if encrypted with `--compress`).
- `--force`: Force overwrite of existing output files without prompting.
- `--backup`: Create a backup of input files (`.bak` extension).
- `--verbose`: Enable detailed output for operations.
- `--config`: Path to an INI configuration file for default settings.
- `-h/--help`: Show the help message and exit.

**Examples**:

1. **Decrypt a Single File with a Key File**:
   ```bash
   python decrypt.py -i example.txt.encrypted -o decrypted.txt -k secret.key --verbose
   ```
   Loads `secret.key`, decrypts `example.txt.encrypted`, and saves the result to `decrypted.txt`.

2. **Decrypt a File with a Password**:
   ```bash
   python decrypt.py -i example.txt.encrypted -o decrypted.txt --password mysecurepassword --decompress --verify-hash
   ```
   Derives the key from the password, decompresses, verifies the hash, and decrypts the file. Requires `salt.bin`.

3. **Decrypt Multiple Files**:
   ```bash
   python decrypt.py -i file1.txt.encrypted file2.txt.encrypted -o output_dir -k secret.key --backup
   ```
   Decrypts `file1.txt.encrypted` and `file2.txt.encrypted`, saves results to `output_dir/file1.txt` and `output_dir/file2.txt`, and creates backups.

4. **Decrypt a Directory**:
   ```bash
   python decrypt.py -i output_dir -o decrypted_dir -k secret.key --force --verbose
   ```
   Decrypts all `.encrypted` files in `output_dir`, preserving directory structure in `decrypted_dir`.

5. **Using a Configuration File**:
   Create `config.ini`:
   ```ini
   [DEFAULT]
   input = example.txt.encrypted
   output = decrypted_dir
   key = secret.key
   decompress = True
   verify_hash = True
   backup = True
   verbose = True
   ```
   Run:
   ```bash
   python decrypt.py --config config.ini
   ```

6. **Show Help**:
   ```bash
   python decrypt.py -h
   ```

## Notes

- **Key Compatibility**: Use the same key file or password (with `salt.bin`) for encryption and decryption.
- **Compression**: If a file was encrypted with `--compress`, use `--decompress` during decryption.
- **Hash Verification**: Requires the `.hash` file generated during encryption. Use `--verify-hash` to enable.
- **Configuration File**: Supports all flags except `--password`, `--rotate-key`, and `--new-key` for security.
- **Backups**: Created with `.bak` extension in the same directory as the input file.
- **Progress Bar**: Automatically displayed for large files using `tqdm`.
- **Directory Processing**: Preserves directory structure; encryption appends `.encrypted`, decryption removes it.

**Credits**: Developed with Grok's assistance. Even Grok is not immune to getting stuck in a repetitive loop. For example, I kept asking it to produce a README in Markdown; however, it only provided part of it in a snippet and the rest as formatted markdown. I then had to paste the entire text and prompt it to generate the equivalent Markdown so that I could copy and paste the entire text from a single snippet.

**Note**: The very first commit was implemented in 3 minutes; double-checking and proofreading added the extra 2 minutes. The entire project took around 20 minutes.
