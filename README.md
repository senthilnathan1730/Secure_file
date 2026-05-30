# 🔐 SecureFile — AES-256-GCM Encryption System

**Author:** Senthil Nathan  
**Security:** AES-256-GCM + PBKDF2-HMAC-SHA256 (600,000 iterations)

---

## 📦 Installation

```bash
pip install -r requirements.txt
```

---

## 🌐 Web App (Flask)

```bash
python app.py
# Open: http://localhost:5000
```

**Features:**
- Drag & drop file upload
- Encrypt / Decrypt via browser
- Supports files up to 500 MB
- Auto-deletes originals after processing

---

## 💻 CLI Tool

```bash
# Encrypt
python securefile_cli.py encrypt secret.pdf
python securefile_cli.py encrypt video.mp4 -o video_safe.secf
python securefile_cli.py encrypt photo.jpg --delete-original

# Decrypt
python securefile_cli.py decrypt secret.secf
python securefile_cli.py decrypt video_safe.secf -o restored_video.mp4

# Inspect .secf file (no password needed)
python securefile_cli.py info secret.secf
```

---

## 🖥 GUI App (Tkinter)

```bash
python securefile_gui.py
```

---

## 🔐 Security Architecture

| Property       | Value                          |
|---------------|-------------------------------|
| Cipher         | AES-256-GCM                   |
| Key derivation | PBKDF2-HMAC-SHA256            |
| Iterations     | 600,000 (NIST recommended)   |
| Salt           | 256-bit (random per file)     |
| Nonce/IV       | 96-bit (random per file)      |
| Auth tag       | 128-bit (tamper detection)    |
| AAD            | File metadata (authenticated) |

### .secf File Format

```
[salt: 32 bytes][nonce: 12 bytes][aad_len: 4 bytes][aad: N bytes][ciphertext + tag]
```

---

## 📂 Supported Formats

- **Documents:** PDF, DOCX, TXT, XLSX, CSV, PPTX
- **Images:** JPG, PNG, GIF, WEBP, BMP, SVG
- **Videos:** MP4, AVI, MKV, MOV, WEBM, FLV
- **Audio:** MP3, WAV, FLAC, AAC, OGG
- **Archives:** ZIP, TAR, GZ, RAR
- **Any binary file**

---

## ⚠ Important

- **Passwords are NEVER stored.** Losing your password means losing the file permanently.
- Each file gets a **unique random salt and nonce** — encrypting the same file twice produces different output.
- **GCM authentication** ensures any tampering is detected on decryption.
