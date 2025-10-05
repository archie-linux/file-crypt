import sys
sys.path.append('/Users/anish/anpa6841/github-projects/crypto_tools')

from flask import Flask, request, send_file, jsonify
import os
import tempfile
import uuid
from werkzeug.utils import secure_filename
from crypto_tools.crypto_utils import derive_key, generate_key, load_key, encrypt_file, decrypt_file, rotate_key
from crypto_tools.file_utils import create_output_path
from crypto_tools.config_utils import load_config

app = Flask(__name__)
UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {''}  # Allow all extensions for flexibility
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    """Check if the file extension is allowed (placeholder for future restrictions)."""
    return True  # Allow all files for now

def save_uploaded_file(file):
    """Save uploaded file securely and return its path."""
    if file and allowed_file(file.filename):
        filename = secure_filename(f"{uuid.uuid4()}_{file.filename}")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        return file_path
    return None

def cleanup_files(*file_paths):
    """Remove temporary files."""
    for path in file_paths:
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass

@app.route('/encrypt', methods=['POST'])
def encrypt():
    """Encrypt a file with optional compression and password/key file."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    password = request.form.get('password')
    key_file = request.files.get('key_file')
    compress = request.form.get('compress', 'false').lower() == 'true'
    force = request.form.get('force', 'false').lower() == 'true'
    backup = request.form.get('backup', 'false').lower() == 'true'
    verbose = request.form.get('verbose', 'false').lower() == 'true'

    input_path = save_uploaded_file(file)
    if not input_path:
        return jsonify({'error': 'Invalid file'}), 400

    output_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{uuid.uuid4()}_encrypted")
    key_path = None

    try:
        if password:
            key = derive_key(password)
            if verbose:
                print("Key derived from password.")
        elif key_file:
            key_path = save_uploaded_file(key_file)
            if not key_path:
                cleanup_files(input_path)
                return jsonify({'error': 'Invalid key file'}), 400
            key = load_key(key_path)
        else:
            key_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{uuid.uuid4()}_secret.key")
            key = generate_key(key_path)

        encrypt_file(input_path, output_path, key, compress=compress, force=force, backup=backup, verbose=verbose)
        
        response = send_file(output_path, as_attachment=True, download_name=f"{secure_filename(file.filename)}.encrypted")
        cleanup_files(input_path, output_path, key_path, output_path + '.hash')
        return response

    except Exception as e:
        cleanup_files(input_path, output_path, key_path, output_path + '.hash')
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    """Decrypt a file with optional decompression and hash verification."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    password = request.form.get('password')
    key_file = request.files.get('key_file')
    verify_hash = request.form.get('verify_hash', 'false').lower() == 'true'
    decompress = request.form.get('decompress', 'false').lower() == 'true'
    force = request.form.get('force', 'false').lower() == 'true'
    backup = request.form.get('backup', 'false').lower() == 'true'
    verbose = request.form.get('verbose', 'false').lower() == 'true'

    input_path = save_uploaded_file(file)
    if not input_path:
        return jsonify({'error': 'Invalid file'}), 400

    output_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{uuid.uuid4()}_decrypted")
    key_path = None

    try:
        if password:
            key = derive_key(password)
            if verbose:
                print("Key derived from password.")
        elif key_file:
            key_path = save_uploaded_file(key_file)
            if not key_path:
                cleanup_files(input_path)
                return jsonify({'error': 'Invalid key file'}), 400
            key = load_key(key_path)
        else:
            cleanup_files(input_path)
            return jsonify({'error': 'Key file or password required'}), 400

        decrypt_file(input_path, output_path, key, verify_hash=verify_hash, decompress=decompress, force=force, backup=backup, verbose=verbose)
        
        response = send_file(output_path, as_attachment=True, download_name=secure_filename(file.filename).replace('.encrypted', ''))
        cleanup_files(input_path, output_path, key_path)
        return response

    except Exception as e:
        cleanup_files(input_path, output_path, key_path)
        return jsonify({'error': str(e)}), 500

@app.route('/rotate_key', methods=['POST'])
def rotate_key_endpoint():
    """Rotate the encryption key for a file."""
    if 'file' not in request.files or 'old_key_file' not in request.files:
        return jsonify({'error': 'File and old key file required'}), 400
    
    file = request.files['file']
    old_key_file = request.files['old_key_file']
    new_key_file = request.files.get('new_key_file')
    compress = request.form.get('compress', 'false').lower() == 'true'
    force = request.form.get('force', 'false').lower() == 'true'
    backup = request.form.get('backup', 'false').lower() == 'true'
    verbose = request.form.get('verbose', 'false').lower() == 'true'

    input_path = save_uploaded_file(file)
    old_key_path = save_uploaded_file(old_key_file)
    if not input_path or not old_key_path:
        cleanup_files(input_path, old_key_path)
        return jsonify({'error': 'Invalid file or old key file'}), 400

    output_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{uuid.uuid4()}_rotated")
    new_key_path = None

    try:
        old_key = load_key(old_key_path)
        if new_key_file:
            new_key_path = save_uploaded_file(new_key_file)
            if not new_key_path:
                cleanup_files(input_path, old_key_path)
                return jsonify({'error': 'Invalid new key file'}), 400
            new_key = load_key(new_key_path)
        else:
            new_key_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{uuid.uuid4()}_new_secret.key")
            new_key = generate_key(new_key_path)

        rotate_key(input_path, output_path, old_key, new_key, compress=compress, force=force, backup=backup, verbose=verbose)
        
        response = send_file(output_path, as_attachment=True, download_name=f"{secure_filename(file.filename)}_rotated.encrypted")
        cleanup_files(input_path, old_key_path, new_key_path, output_path, output_path + '.hash')
        return response

    except Exception as e:
        cleanup_files(input_path, old_key_path, new_key_path, output_path, output_path + '.hash')
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
