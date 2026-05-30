import os
import json
import base64
import hashlib
import secrets
import mimetypes
from pathlib import Path
from flask import Flask, request, jsonify, send_file, render_template
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500 MB
app.config['SECRET_KEY'] = secrets.token_hex(32)

BASE_DIR = Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "uploads"
ENCRYPTED_DIR = BASE_DIR / "encrypted"
DECRYPTED_DIR = BASE_DIR / "decrypted"

for d in [UPLOAD_DIR, ENCRYPTED_DIR, DECRYPTED_DIR]:
    d.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {
    # Documents
    'pdf', 'docx', 'doc', 'txt', 'xlsx', 'xls', 'pptx', 'ppt', 'csv', 'odt',
    # Images
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg', 'tiff', 'ico',
    # Videos
    'mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm', 'm4v', '3gp',
    # Audio
    'mp3', 'wav', 'flac', 'aac', 'ogg', 'm4a',
    # Archives
    'zip', 'tar', 'gz', 'rar', '7z',
    # Code
    'py', 'js', 'html', 'css', 'json', 'xml', 'yaml', 'sh'
}


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive AES-256 key from password using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations=600_000,  # NIST recommended
        dklen=32  # 256-bit key
    )


def encrypt_file(file_path: Path, password: str) -> dict:
    """Encrypt a file using AES-256-GCM."""
    salt = secrets.token_bytes(32)       # 256-bit salt
    nonce = secrets.token_bytes(12)      # 96-bit nonce for GCM

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    original_filename = file_path.name
    original_extension = file_path.suffix.lower()

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Encrypt with file metadata as AAD (authenticated additional data)
    aad = json.dumps({
        "filename": original_filename,
        "extension": original_extension,
        "size": len(plaintext)
    }).encode()

    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    # Build encrypted file: [salt(32)][nonce(12)][aad_len(4)][aad][ciphertext+tag]
    aad_len = len(aad).to_bytes(4, 'big')
    encrypted_data = salt + nonce + aad_len + aad + ciphertext

    # Save as .secf (SecureFile encrypted)
    enc_filename = secure_filename(file_path.stem) + ".secf"
    enc_path = ENCRYPTED_DIR / enc_filename

    # Handle name collisions
    counter = 1
    while enc_path.exists():
        enc_path = ENCRYPTED_DIR / f"{secure_filename(file_path.stem)}_{counter}.secf"
        counter += 1

    with open(enc_path, 'wb') as f:
        f.write(encrypted_data)

    return {
        "success": True,
        "original_file": original_filename,
        "encrypted_file": enc_path.name,
        "original_size": len(plaintext),
        "encrypted_size": len(encrypted_data),
        "algorithm": "AES-256-GCM",
        "kdf": "PBKDF2-HMAC-SHA256 (600,000 iterations)",
        "salt_bits": 256,
        "nonce_bits": 96
    }


def decrypt_file(file_path: Path, password: str) -> dict:
    """Decrypt a .secf file using AES-256-GCM."""
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    if len(encrypted_data) < 48:
        raise ValueError("Invalid or corrupted encrypted file.")

    # Parse the encrypted file structure
    offset = 0
    salt = encrypted_data[offset:offset + 32];    offset += 32
    nonce = encrypted_data[offset:offset + 12];   offset += 12
    aad_len = int.from_bytes(encrypted_data[offset:offset + 4], 'big'); offset += 4
    aad = encrypted_data[offset:offset + aad_len]; offset += aad_len
    ciphertext = encrypted_data[offset:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    except Exception:
        raise ValueError("Decryption failed. Wrong password or corrupted file.")

    metadata = json.loads(aad.decode())
    original_filename = metadata["filename"]
    original_extension = metadata["extension"]

    dec_filename = secure_filename(Path(original_filename).stem) + original_extension
    dec_path = DECRYPTED_DIR / dec_filename

    counter = 1
    while dec_path.exists():
        dec_path = DECRYPTED_DIR / f"{secure_filename(Path(original_filename).stem)}_{counter}{original_extension}"
        counter += 1

    with open(dec_path, 'wb') as f:
        f.write(plaintext)

    return {
        "success": True,
        "encrypted_file": file_path.name,
        "decrypted_file": dec_path.name,
        "original_filename": original_filename,
        "decrypted_size": len(plaintext),
        "algorithm": "AES-256-GCM",
        "dec_path": str(dec_path)
    }


def get_file_category(filename: str) -> str:
    ext = Path(filename).suffix.lower().lstrip('.')
    if ext in {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg', 'tiff', 'ico'}:
        return 'image'
    elif ext in {'mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm', 'm4v', '3gp'}:
        return 'video'
    elif ext in {'mp3', 'wav', 'flac', 'aac', 'ogg', 'm4a'}:
        return 'audio'
    elif ext in {'pdf', 'docx', 'doc', 'txt', 'xlsx', 'pptx', 'csv', 'odt'}:
        return 'document'
    elif ext == 'secf':
        return 'encrypted'
    else:
        return 'other'


def format_size(size_bytes: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file provided"}), 400

    file = request.files['file']
    password = request.form.get('password', '')

    if not file.filename:
        return jsonify({"success": False, "error": "No file selected"}), 400
    if not password or len(password) < 6:
        return jsonify({"success": False, "error": "Password must be at least 6 characters"}), 400

    ext = Path(file.filename).suffix.lower().lstrip('.')
    if ext not in ALLOWED_EXTENSIONS and ext != '':
        return jsonify({"success": False, "error": f"File type '.{ext}' not supported"}), 400

    filename = secure_filename(file.filename)
    upload_path = UPLOAD_DIR / filename

    counter = 1
    while upload_path.exists():
        upload_path = UPLOAD_DIR / f"{Path(filename).stem}_{counter}{Path(filename).suffix}"
        counter += 1

    file.save(str(upload_path))

    try:
        result = encrypt_file(upload_path, password)
        result["original_size_fmt"] = format_size(result["original_size"])
        result["encrypted_size_fmt"] = format_size(result["encrypted_size"])
        result["category"] = get_file_category(file.filename)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if upload_path.exists():
            upload_path.unlink()


@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file provided"}), 400

    file = request.files['file']
    password = request.form.get('password', '')

    if not file.filename:
        return jsonify({"success": False, "error": "No file selected"}), 400
    if not password:
        return jsonify({"success": False, "error": "Password is required"}), 400
    if not file.filename.endswith('.secf'):
        return jsonify({"success": False, "error": "Only .secf encrypted files can be decrypted"}), 400

    filename = secure_filename(file.filename)
    upload_path = UPLOAD_DIR / filename
    file.save(str(upload_path))

    try:
        result = decrypt_file(upload_path, password)
        result["decrypted_size_fmt"] = format_size(result["decrypted_size"])
        result["category"] = get_file_category(result["original_filename"])
        return jsonify(result)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Unexpected error: {str(e)}"}), 500
    finally:
        if upload_path.exists():
            upload_path.unlink()


@app.route('/api/download/encrypted/<filename>')
def download_encrypted(filename):
    safe = secure_filename(filename)
    path = ENCRYPTED_DIR / safe
    if not path.exists():
        return jsonify({"error": "File not found"}), 404
    return send_file(str(path), as_attachment=True, download_name=safe)


@app.route('/api/download/decrypted/<filename>')
def download_decrypted(filename):
    safe = secure_filename(filename)
    path = DECRYPTED_DIR / safe
    if not path.exists():
        return jsonify({"error": "File not found"}), 404
    mime = mimetypes.guess_type(safe)[0] or 'application/octet-stream'
    return send_file(str(path), as_attachment=True, download_name=safe, mimetype=mime)


@app.route('/api/supported-formats')
def supported_formats():
    return jsonify({
        "documents": ['pdf', 'docx', 'doc', 'txt', 'xlsx', 'csv', 'pptx'],
        "images": ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg'],
        "videos": ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'webm'],
        "audio": ['mp3', 'wav', 'flac', 'aac', 'ogg'],
        "archives": ['zip', 'tar', 'gz', 'rar'],
        "decrypt": ['secf']
    })


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
