import sys
import os
import logging
import json
import uuid
from filelock import FileLock
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'crypto_tools')))
from flask import Flask, request, send_file, render_template
from werkzeug.utils import secure_filename
try:
    from crypto_tools.crypto_utils import derive_key, generate_key, load_key, encrypt_file, decrypt_file, rotate_key
    from crypto_tools.file_utils import collect_files, create_output_path
except ImportError as e:
    print(f"Failed to import crypto_tools: {e}")
    raise

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'enc', 'encrypted', 'key'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
SUBFOLDERS = ['encrypted_files', 'keys', 'decrypted_files', 'rotated_files']
METADATA_FILE = os.path.join(UPLOAD_FOLDER, 'metadata.json')

# Create folders and metadata file
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
for subfolder in SUBFOLDERS:
    os.makedirs(os.path.join(UPLOAD_FOLDER, subfolder), exist_ok=True)
if not os.path.exists(METADATA_FILE):
    with open(METADATA_FILE, 'w') as f:
        json.dump([], f)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def read_metadata():
    with FileLock(METADATA_FILE + '.lock'):
        try:
            with open(METADATA_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to read metadata: {str(e)}")
            return []

def write_metadata(data):
    with FileLock(METADATA_FILE + '.lock'):
        try:
            with open(METADATA_FILE, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to write metadata: {str(e)}")
            raise

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['GET'])
def encrypt_page():
    return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET'])
def decrypt_page():
    metadata = read_metadata()
    encrypted_files = [entry for entry in metadata if entry['encrypted_file']]
    return render_template('decrypt.html', encrypted_files=encrypted_files)

@app.route('/rotate_key', methods=['GET'])
def rotate_key_page():
    metadata = read_metadata()
    encrypted_files = [entry for entry in metadata if entry['encrypted_file']]
    return render_template('rotate_key.html', encrypted_files=encrypted_files)

@app.route('/summary', methods=['GET'])
def summary_page():
    try:
        metadata = read_metadata()
        logger.debug(f"Loaded {len(metadata)} metadata entries")
        return render_template('summary.html', metadata=metadata)
    except Exception as e:
        logger.error(f"Failed to load summary: {str(e)}")
        return render_template('result.html', error=f"Failed to load summary: {str(e)}", status=500)

@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    logger.debug("Received request to /api/encrypt")
    logger.debug(f"Form data: {request.form}")
    logger.debug(f"Files: {request.files.keys()}")

    if 'files[]' not in request.files and 'directory' not in request.files:
        logger.error("No files or directory provided")
        return render_template('result.html', error="No files or directory provided", status=400)

    files = request.files.getlist('files[]')
    directory = request.files.get('directory')
    password = request.form.get('password')
    key_file = request.files.get('key_file') if 'key_file' in request.files else None
    compress = request.form.get('compress', 'false').lower() == 'true'
    force = request.form.get('force', 'false').lower() == 'true'
    backup = request.form.get('backup', 'false').lower() == 'true'
    verbose = request.form.get('verbose', 'false').lower() == 'true'

    # Handle key
    generated_key_path = None
    key_identifier = None
    try:
        if password:
            key = derive_key(password)
            key_identifier = "Password"
            logger.debug("Derived key from password")
        elif key_file:
            if password:
                logger.error("Provide either password or key file, not both")
                return render_template('result.html', error="Provide either password or key file, not both", status=400)
            key_filename = secure_filename(key_file.filename)
            key_path = os.path.join(app.config['UPLOAD_FOLDER'], 'keys', key_filename)
            key_file.save(key_path)
            if not os.path.exists(key_path):
                logger.error(f"Key file not saved: {key_path}")
                raise FileNotFoundError(f"Key file not saved: {key_path}")
            key = load_key(key_path)
            key_identifier = os.path.join('keys', key_filename)
            logger.debug(f"Loaded key from {key_path}")
        else:
            key_filename = f'generated_key_{uuid.uuid4().hex}.key'
            generated_key_path = os.path.join(app.config['UPLOAD_FOLDER'], 'keys', key_filename)
            try:
                key = generate_key(generated_key_path)
                if not os.path.exists(generated_key_path):
                    logger.error(f"Key file not created: {generated_key_path}")
                    raise FileNotFoundError(f"Key file not created: {generated_key_path}")
                logger.debug(f"Generated key at {generated_key_path}")
            except Exception as e:
                logger.error(f"Key generation failed for {generated_key_path}: {str(e)}")
                raise
            key_identifier = os.path.join('keys', key_filename)
    except Exception as e:
        logger.error(f"Key handling failed: {str(e)}")
        return render_template('result.html', error=f"Key handling failed: {str(e)}", status=500)

    output_files = []
    verbose_output = []
    metadata = read_metadata()
    operation_id = uuid.uuid4().hex

    # Handle directory upload
    try:
        if directory:
            dir_filename = secure_filename(directory.filename)
            dir_path = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted_files', dir_filename)
            directory.save(dir_path)
            input_files = collect_files([dir_path])
            logger.debug(f"Collected {len(input_files)} files from directory {dir_path}")
        else:
            input_files = []
            for file in files:
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted_files', filename)
                    file.save(file_path)
                    input_files.append(file_path)
            logger.debug(f"Received {len(input_files)} files")
    except Exception as e:
        logger.error(f"File upload failed: {str(e)}")
        return render_template('result.html', error=f"File upload failed: {str(e)}", status=500)

    # Process files
    output_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted_files', f'encrypted_{uuid.uuid4().hex}')
    os.makedirs(output_dir, exist_ok=True)

    for input_file in input_files:
        output_file = create_output_path(input_file, output_dir, input_file, suffix=None)
        output_file = output_file + '.encrypted'
        try:
            encrypt_file(input_file, output_file, key, compress=compress, force=force, backup=backup, verbose=verbose)
            output_files.append(output_file)
            relative_output_file = os.path.relpath(output_file, app.config['UPLOAD_FOLDER'])
            metadata.append({
                'encrypted_file': relative_output_file,
                'key_used': key_identifier,
                'decrypted_file': None,
                'operation_id': operation_id,
                'encrypt_zip_path': None,
                'decrypt_zip_path': None,
                'rotate_zip_path': None
            })
            if verbose:
                verbose_output.append(f"Encrypted {input_file} to {output_file}")
        except Exception as e:
            verbose_output.append(f"Error encrypting {input_file}: {str(e)}")
            logger.error(f"Encryption failed for {input_file}: {str(e)}")

    # Create zip of encrypted files
    try:
        zip_filename = f'encrypted_files_{uuid.uuid4().hex}.zip'
        zip_path = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted_files', zip_filename)
        import shutil
        shutil.make_archive(zip_path.replace('.zip', ''), 'zip', output_dir)
        logger.debug(f"Created zip at {zip_path}")
        # Update metadata with encrypt_zip_path
        relative_zip_path = os.path.relpath(zip_path, app.config['UPLOAD_FOLDER'])
        for entry in metadata:
            if entry['operation_id'] == operation_id:
                entry['encrypt_zip_path'] = relative_zip_path
    except Exception as e:
        logger.error(f"Zip creation failed: {str(e)}")
        return render_template('result.html', error=f"Zip creation failed: {str(e)}", status=500)

    # Update metadata
    try:
        write_metadata(metadata)
    except Exception as e:
        logger.error(f"Metadata update failed: {str(e)}")
        return render_template('result.html', error=f"Metadata update failed: {str(e)}", status=500)

    response = {
        'message': 'Encryption completed',
        'output_files': output_files,
        'zip_path': relative_zip_path,
        'verbose_output': verbose_output
    }
    if generated_key_path:
        response['generated_key_path'] = os.path.join('keys', key_filename)
    logger.debug(f"Response: {response}")
    return render_template('result.html', data=response, status=200)

@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    logger.debug("Received request to /api/decrypt")
    logger.debug(f"Form data: {request.form}")
    logger.debug(f"Files: {request.files.keys()}")

    selected_files = request.form.getlist('encrypted_files')
    directory = request.files.get('directory') if 'directory' in request.files else None
    password = request.form.get('password')
    verify_hash = request.form.get('verify_hash', 'false').lower() == 'true'
    decompress = request.form.get('decompress', 'false').lower() == 'true'
    force = request.form.get('force', 'false').lower() == 'true'
    backup = request.form.get('backup', 'false').lower() == 'true'
    verbose = request.form.get('verbose', 'false').lower() == 'true'

    if not selected_files and not directory:
        logger.error("No files or directory selected")
        return render_template('result.html', error="No files or directory selected", status=400)

    metadata = read_metadata()
    output_files = []
    verbose_output = []
    input_files = []
    operation_id = uuid.uuid4().hex

    # Handle selected files from dropdown
    if selected_files:
        for selected_file in selected_files:
            for entry in metadata:
                if entry['encrypted_file'] == selected_file:
                    input_files.append(os.path.join(app.config['UPLOAD_FOLDER'], selected_file))
                    break

    # Handle directory upload
    if directory:
        try:
            dir_filename = secure_filename(directory.filename)
            dir_path = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted_files', dir_filename)
            directory.save(dir_path)
            dir_files = collect_files([dir_path], extension_filter='.encrypted')
            input_files.extend(dir_files)
            logger.debug(f"Collected {len(dir_files)} files from directory {dir_path}")
        except Exception as e:
            logger.error(f"Directory upload failed: {str(e)}")
            return render_template('result.html', error=f"Directory upload failed: {str(e)}", status=500)

    if not input_files:
        logger.error("No valid encrypted files found")
        return render_template('result.html', error="No valid encrypted files found", status=400)

    # Process decryption
    output_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted_files', f'decrypted_{uuid.uuid4().hex}')
    os.makedirs(output_dir, exist_ok=True)

    for input_file in input_files:
        relative_input_file = os.path.relpath(input_file, app.config['UPLOAD_FOLDER'])
        key_path = None
        key = None

        # Find key from metadata
        for entry in metadata:
            if entry['encrypted_file'] == relative_input_file:
                if entry['key_used'] == 'Password':
                    if not password:
                        verbose_output.append(f"Password required for {input_file}")
                        continue
                    key = derive_key(password)
                else:
                    key_path = os.path.join(app.config['UPLOAD_FOLDER'], entry['key_used'])
                    if not os.path.exists(key_path):
                        verbose_output.append(f"Key file {entry['key_used']} not found for {input_file}")
                        logger.error(f"Key file missing: {key_path}")
                        continue
                    try:
                        key = load_key(key_path)
                        logger.debug(f"Loaded key from {key_path}")
                    except Exception as e:
                        verbose_output.append(f"Failed to load key {entry['key_used']} for {input_file}: {str(e)}")
                        logger.error(f"Key load failed for {key_path}: {str(e)}")
                        continue
                break
        else:
            verbose_output.append(f"No metadata entry found for {input_file}")
            continue

        if not key:
            verbose_output.append(f"Skipping {input_file}: No valid key provided")
            continue

        output_file = create_output_path(input_file, output_dir, input_file, suffix='.encrypted')
        try:
            decrypt_file(input_file, output_file, key, verify_hash=verify_hash, decompress=decompress, force=force, backup=backup, verbose=verbose)
            output_files.append(output_file)
            relative_output_file = os.path.relpath(output_file, app.config['UPLOAD_FOLDER'])
            for entry in metadata:
                if entry['encrypted_file'] == relative_input_file:
                    entry['decrypted_file'] = relative_output_file
                    entry['operation_id'] = operation_id
                    entry['decrypt_zip_path'] = None  # Will be updated after zip creation
                    break
            if verbose:
                verbose_output.append(f"Decrypted {input_file} to {output_file}")
        except Exception as e:
            verbose_output.append(f"Error decrypting {input_file}: {str(e)}")
            logger.error(f"Decryption failed for {input_file}: {str(e)}")

    # Create zip of decrypted files
    try:
        zip_filename = f'decrypted_files_{uuid.uuid4().hex}.zip'
        zip_path = os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted_files', zip_filename)
        import shutil
        shutil.make_archive(zip_path.replace('.zip', ''), 'zip', output_dir)
        logger.debug(f"Created zip at {zip_path}")
        # Update metadata with decrypt_zip_path
        relative_zip_path = os.path.relpath(zip_path, app.config['UPLOAD_FOLDER'])
        for entry in metadata:
            if entry['operation_id'] == operation_id:
                entry['decrypt_zip_path'] = relative_zip_path
    except Exception as e:
        logger.error(f"Zip creation failed: {str(e)}")
        return render_template('result.html', error=f"Zip creation failed: {str(e)}", status=500)

    # Update metadata
    try:
        write_metadata(metadata)
    except Exception as e:
        logger.error(f"Metadata update failed: {str(e)}")
        return render_template('result.html', error=f"Metadata update failed: {str(e)}", status=500)

    response = {
        'message': 'Decryption completed',
        'output_files': output_files,
        'zip_path': relative_zip_path,
        'verbose_output': verbose_output
    }
    logger.debug(f"Response: {response}")
    return render_template('result.html', data=response, status=200)

@app.route('/api/rotate_key', methods=['POST'])
@app.route('/api/rotate_key', methods=['POST'])
def api_rotate_key():
    logger.debug("Received request to /api/rotate_key")
    logger.debug(f"Form data: {request.form}")
    logger.debug(f"Files: {request.files.keys()}")

    selected_files = request.form.getlist('encrypted_files')
    password = request.form.get('password')
    new_key_file = request.files.get('new_key_file') if 'new_key_file' in request.files else None
    compress = request.form.get('compress', 'false').lower() == 'true'
    force = request.form.get('force', 'false').lower() == 'true'
    backup = request.form.get('backup', 'false').lower() == 'true'
    verbose = request.form.get('verbose', 'false').lower() == 'true'

    if not selected_files:
        logger.error("No encrypted files selected")
        return render_template('result.html', error="No encrypted files selected", status=400)

    metadata = read_metadata()
    output_files = []
    verbose_output = []
    input_files = []
    operation_id = uuid.uuid4().hex

    # Handle selected files from dropdown
    for selected_file in selected_files:
        for entry in metadata:
            if entry['encrypted_file'] == selected_file:
                input_files.append(os.path.join(app.config['UPLOAD_FOLDER'], selected_file))
                break

    if not input_files:
        logger.error("No valid encrypted files found")
        return render_template('result.html', error="No valid encrypted files found", status=400)

    # Handle new key
    try:
        if new_key_file:
            new_key_filename = secure_filename(new_key_file.filename)
            new_key_path = os.path.join(app.config['UPLOAD_FOLDER'], 'keys', new_key_filename)
            new_key_file.save(new_key_path)
            if not os.path.exists(new_key_path):
                logger.error(f"New key file not saved: {new_key_path}")
                raise FileNotFoundError(f"New key file not saved: {new_key_path}")
            new_key = load_key(new_key_path)
            new_key_identifier = os.path.join('keys', new_key_filename)
            logger.debug(f"Loaded new key from {new_key_path}")
        else:
            new_key_filename = f'new_key_{uuid.uuid4().hex}.key'
            new_key_path = os.path.join(app.config['UPLOAD_FOLDER'], 'keys', new_key_filename)
            try:
                new_key = generate_key(new_key_path)
                if not os.path.exists(new_key_path):
                    logger.error(f"New key file not created: {new_key_path}")
                    raise FileNotFoundError(f"New key file not created: {new_key_path}")
                logger.debug(f"Generated new key at {new_key_path}")
            except Exception as e:
                logger.error(f"New key generation failed for {new_key_path}: {str(e)}")
                raise
            new_key_identifier = os.path.join('keys', new_key_filename)
    except Exception as e:
        logger.error(f"New key handling failed: {str(e)}")
        return render_template('result.html', error=f"New key handling failed: {str(e)}", status=500)

    # Process key rotation
    output_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'rotated_files', f'rotated_{uuid.uuid4().hex}')
    os.makedirs(output_dir, exist_ok=True)

    for input_file in input_files:
        relative_input_file = os.path.relpath(input_file, app.config['UPLOAD_FOLDER'])
        old_key = None

        # Find old key from metadata
        for entry in metadata:
            if entry['encrypted_file'] == relative_input_file:
                if entry['key_used'] == 'Password':
                    if not password:
                        verbose_output.append(f"Password required for {input_file}")
                        continue
                    old_key = derive_key(password)
                else:
                    old_key_path = os.path.join(app.config['UPLOAD_FOLDER'], entry['key_used'])
                    if not os.path.exists(old_key_path):
                        verbose_output.append(f"Old key file {entry['key_used']} not found for {input_file}")
                        logger.error(f"Old key file missing: {old_key_path}")
                        continue
                    try:
                        old_key = load_key(old_key_path)
                        logger.debug(f"Loaded old key from {old_key_path}")
                    except Exception as e:
                        verbose_output.append(f"Failed to load old key {entry['key_used']} for {input_file}: {str(e)}")
                        logger.error(f"Old key load failed for {old_key_path}: {str(e)}")
                        continue
                break
        else:
            verbose_output.append(f"No metadata entry found for {input_file}")
            continue

        if not old_key:
            verbose_output.append(f"Skipping {input_file}: No valid old key provided")
            continue

        output_filename = f'rotated_{os.path.basename(input_file)}'
        output_path = os.path.join(output_dir, output_filename)
        try:
            rotate_key(input_file, output_path, old_key, new_key, compress=compress, force=force, backup=backup, verbose=verbose)
            output_files.append(output_path)
            relative_output_file = os.path.relpath(output_path, app.config['UPLOAD_FOLDER'])
            for entry in metadata:
                if entry['encrypted_file'] == relative_input_file:
                    entry['encrypted_file'] = relative_output_file
                    entry['key_used'] = new_key_identifier
                    entry['decrypted_file'] = None
                    entry['operation_id'] = operation_id
                    entry['encrypt_zip_path'] = None  # Will be updated after zip creation
                    entry['decrypt_zip_path'] = None  # Clear since file is re-encrypted
                    break
            else:
                metadata.append({
                    'encrypted_file': relative_output_file,
                    'key_used': new_key_identifier,
                    'decrypted_file': None,
                    'operation_id': operation_id,
                    'encrypt_zip_path': None,
                    'decrypt_zip_path': None
                })
            if verbose:
                verbose_output.append(f"Rotated key for {input_file} to {output_path}")
        except Exception as e:
            verbose_output.append(f"Error rotating key for {input_file}: {str(e)}")
            logger.error(f"Key rotation failed for {input_file}: {str(e)}")

    # Create zip of rotated files
    try:
        zip_filename = f'rotated_files_{uuid.uuid4().hex}.zip'
        zip_path = os.path.join(app.config['UPLOAD_FOLDER'], 'rotated_files', zip_filename)
        import shutil
        shutil.make_archive(zip_path.replace('.zip', ''), 'zip', output_dir)
        logger.debug(f"Created zip at {zip_path}")
        # Update metadata with encrypt_zip_path
        relative_zip_path = os.path.relpath(zip_path, app.config['UPLOAD_FOLDER'])
        for entry in metadata:
            if entry['operation_id'] == operation_id:
                entry['encrypt_zip_path'] = relative_zip_path
    except Exception as e:
        logger.error(f"Zip creation failed: {str(e)}")
        return render_template('result.html', error=f"Zip creation failed: {str(e)}", status=500)

    # Update metadata
    try:
        write_metadata(metadata)
    except Exception as e:
        logger.error(f"Metadata update failed: {str(e)}")
        return render_template('result.html', error=f"Metadata update failed: {str(e)}", status=500)

    response = {
        'message': 'Key rotation completed',
        'output_files': output_files,
        'zip_path': relative_zip_path,
        'new_key_file': new_key_identifier,
        'verbose_output': verbose_output
    }
    logger.debug(f"Response: {response}")
    return render_template('result.html', data=response, status=200)

@app.route('/download/<path:filename>')
def download_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        logger.debug(f"Downloading file: {file_path}")
        return send_file(file_path, as_attachment=True)
    logger.error(f"File not found: {file_path}")
    return render_template('result.html', error="File not found", status=404)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
