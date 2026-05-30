# 🔐 SecureFile CLI — User Manual

> **AES-256-GCM File Encryption Tool** · Command-Line Interface  
> Author: [Senthil Nathan](https://senthil.zeal.ninja) · [senthilnathans1730@gmail.com](mailto:senthilnathans1730@gmail.com)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands Reference](#commands-reference)
  - [encrypt](#encrypt)
  - [decrypt](#decrypt)
  - [info](#info)
- [All Options & Flags](#all-options--flags)
- [Usage Examples](#usage-examples)
- [Security Architecture](#security-architecture)
- [File Format (.secf)](#file-format-secf)
- [Supported File Types](#supported-file-types)
- [Exit Codes](#exit-codes)
- [Tips & Best Practices](#tips--best-practices)
- [Troubleshooting](#troubleshooting)

---

## Overview

`securefile_cli.py` is a command-line tool for encrypting and decrypting any file type using **AES-256-GCM** authenticated encryption. It derives a 256-bit encryption key from your password using **PBKDF2-HMAC-SHA256** with 600,000 iterations, making brute-force attacks computationally infeasible.

Encrypted files are saved with the `.secf` extension and contain all cryptographic parameters (salt, nonce, auth tag) embedded inside — no separate key files needed.

---

## Requirements

| Requirement | Version |
|------------|---------|
| Python | 3.8 or higher |
| cryptography | 42.0.0 or higher |

Check your Python version:
```bash
python --version
# or
python3 --version
```

---

## Installation

**Step 1 — Clone the repository**
```bash
git clone https://github.com/senthilnathan1730/secure_file.git
cd secure_file
```

**Step 2 — Install dependencies**
```bash
pip install -r requirements.txt
```

**Step 3 — Verify installation**
```bash
python securefile_cli.py --help
```

You should see the SecureFile banner and usage information.

---

## Quick Start

```bash
# Encrypt a file (you will be prompted for a password)
python securefile_cli.py encrypt report.pdf

# Decrypt it back
python securefile_cli.py decrypt report.secf

# View what's inside a .secf file (no password needed)
python securefile_cli.py info report.secf
```

---

## Commands Reference

The CLI has three subcommands: `encrypt`, `decrypt`, and `info`.

```
python securefile_cli.py <command> <file> [options]
```

---

### `encrypt`

Encrypts any file and produces a `.secf` encrypted output.

**Syntax:**
```bash
python securefile_cli.py encrypt <FILE> [options]
```

**What happens:**
1. A random 256-bit salt is generated
2. A random 96-bit nonce (IV) is generated
3. A 256-bit AES key is derived from your password using PBKDF2-SHA256
4. The file is encrypted using AES-256-GCM
5. A 128-bit authentication tag is embedded
6. Everything is written to a `.secf` file
7. The original file is **not deleted** (unless `--delete-original` is used)

**Example output:**
```
  ◆  Source file  : report.pdf (1.2 MB)
  ◆  Output file  : report.secf
  ◆  Algorithm    : AES-256-GCM
  ◆  KDF          : PBKDF2-HMAC-SHA256 (600,000 iterations)

  ►  Generating cryptographic parameters…
  ►  Deriving encryption key…
  ►  Reading 1.2 MB…
  ►  Encrypting with AES-256-GCM…

  ✔  Encryption complete!
  ✔  Output        : report.secf
  ✔  Original size : 1.2 MB
  ✔  Encrypted size: 1.2 MB (100.2% of original)
  ✔  GCM auth tag  : Embedded (tamper-proof)
```

---

### `decrypt`

Decrypts a `.secf` file back to its original format.

**Syntax:**
```bash
python securefile_cli.py decrypt <FILE.secf> [options]
```

**What happens:**
1. The salt, nonce, and metadata are read from the `.secf` file
2. The AES-256 key is re-derived from your password
3. AES-256-GCM decrypts the file AND verifies the auth tag
4. If the password is wrong or the file was tampered with, decryption fails safely
5. The original file is restored with its original filename and extension

**Example output:**
```
  ◆  Encrypted file: report.secf (1.2 MB)
  ◆  Algorithm     : AES-256-GCM

  ►  Reading encrypted file…
  ►  Parsing cryptographic header…
  ►  Deriving decryption key…
  ►  Decrypting and verifying integrity…

  ✔  Decryption complete!
  ✔  Output file   : report.pdf
  ✔  Original name : report.pdf
  ✔  File size     : 1.2 MB
  ✔  Integrity     : GCM authentication PASSED ✓
```

---

### `info`

Inspects a `.secf` file and shows its metadata — **no password required**.

**Syntax:**
```bash
python securefile_cli.py info <FILE.secf>
```

**Example output:**
```
  ►  File         : report.secf
  ►  Encrypted sz : 1.2 MB
  ►  Original name: report.pdf
  ►  Original ext : .pdf
  ►  Original size: 1.2 MB
  ►  Algorithm    : AES-256-GCM
  ►  KDF          : PBKDF2-HMAC-SHA256 (600,000 iters)
  ►  Salt         : 256-bit (embedded)
  ►  Nonce        : 96-bit (embedded)
  ►  Auth Tag     : 128-bit GCM tag (embedded)
```

> **Note:** The `info` command only reads public metadata. The actual file contents remain fully encrypted.

---

## All Options & Flags

### `encrypt` options

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `file` | — | Path to the file to encrypt *(required)* | — |
| `--output PATH` | `-o` | Custom output path for the `.secf` file | `<filename>.secf` |
| `--password PASS` | `-p` | Provide password directly in the command | Interactive prompt |
| `--delete-original` | — | Delete the original file after successful encryption | Disabled |

### `decrypt` options

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `file` | — | Path to the `.secf` file to decrypt *(required)* | — |
| `--output PATH` | `-o` | Custom output path for the decrypted file | Original filename |
| `--password PASS` | `-p` | Provide password directly in the command | Interactive prompt |
| `--overwrite` | — | Overwrite the output file if it already exists | Disabled |

### `info` options

| Flag | Description |
|------|-------------|
| `file` | Path to the `.secf` file to inspect *(required)* |

---

## Usage Examples

### Basic Encryption

```bash
# Encrypt a PDF — will prompt for password
python securefile_cli.py encrypt document.pdf

# Output: document.secf (in the same directory)
```

---

### Encrypt with Custom Output Path

```bash
# Save encrypted file to a specific location
python securefile_cli.py encrypt photo.jpg -o /home/user/backup/photo_encrypted.secf
```

---

### Encrypt a Video File

```bash
# Encrypt a large video
python securefile_cli.py encrypt lecture.mp4

# Encrypt and remove the original (use with caution!)
python securefile_cli.py encrypt lecture.mp4 --delete-original
```

---

### Encrypt with Password in Command (Scripting)

```bash
# Pass password inline — useful for scripts and automation
python securefile_cli.py encrypt config.json -p "MyStr0ng@Pass!"

# WARNING: The password may appear in shell history.
# Prefer the interactive prompt for sensitive use.
```

---

### Basic Decryption

```bash
# Decrypt — restores original filename automatically
python securefile_cli.py decrypt document.secf

# Output: document.pdf (original filename from metadata)
```

---

### Decrypt to a Specific Location

```bash
python securefile_cli.py decrypt photo_encrypted.secf -o /home/user/restored/photo.jpg
```

---

### Decrypt and Overwrite an Existing File

```bash
python securefile_cli.py decrypt report.secf --overwrite
```

---

### Inspect a .secf File

```bash
# See what's inside without decrypting it
python securefile_cli.py info lecture.secf
```

---

### Batch Encryption (Shell Script)

```bash
#!/bin/bash
# encrypt_all.sh — Encrypt every PDF in current directory

PASSWORD="YourSecurePassword123!"

for file in *.pdf; do
    echo "Encrypting: $file"
    python securefile_cli.py encrypt "$file" -p "$PASSWORD"
done

echo "Done. All PDFs encrypted."
```

---

### Batch Decryption (Shell Script)

```bash
#!/bin/bash
# decrypt_all.sh — Decrypt every .secf file

PASSWORD="YourSecurePassword123!"

for file in *.secf; do
    echo "Decrypting: $file"
    python securefile_cli.py decrypt "$file" -p "$PASSWORD"
done

echo "Done."
```

---

## Security Architecture

```
Password + Salt  ──►  PBKDF2-HMAC-SHA256  ──►  256-bit AES Key
                       (600,000 iterations)

Plaintext + Nonce + Key  ──►  AES-256-GCM  ──►  Ciphertext + 128-bit Auth Tag
```

| Property | Value | Purpose |
|----------|-------|---------|
| **Cipher** | AES-256-GCM | Encryption + authentication in one pass |
| **Key Size** | 256 bits | Maximum AES security level |
| **KDF** | PBKDF2-HMAC-SHA256 | Converts password to cryptographic key |
| **Iterations** | 600,000 | NIST SP 800-132 recommended (2023) |
| **Salt** | 256-bit random | Prevents rainbow table / precomputation attacks |
| **Nonce (IV)** | 96-bit random | Ensures unique ciphertext per encryption |
| **Auth Tag** | 128-bit GCM | Detects any tampering or corruption |
| **AAD** | File metadata | Filename/extension authenticated but not encrypted |

> **GCM (Galois/Counter Mode)** is an AEAD (Authenticated Encryption with Associated Data) mode. It simultaneously encrypts your data AND produces a cryptographic tag that verifies the data has not been modified. If even a single byte is changed, decryption will fail with an error.

---

## File Format (.secf)

Encrypted files use a custom binary format:

```
┌─────────────────────────────────────────────────────────────────┐
│  Offset   │  Size    │  Field         │  Description            │
├───────────┼──────────┼────────────────┼─────────────────────────┤
│  0        │  32 B    │  Salt          │  PBKDF2 salt (256-bit)  │
│  32       │  12 B    │  Nonce         │  GCM nonce (96-bit)     │
│  44       │  4 B     │  AAD Length    │  Length of metadata     │
│  48       │  N B     │  AAD           │  JSON metadata          │
│  48+N     │  rest    │  Ciphertext    │  Encrypted data + tag   │
└─────────────────────────────────────────────────────────────────┘
```

The **AAD (Additional Authenticated Data)** is a JSON object:
```json
{
  "filename": "report.pdf",
  "extension": ".pdf",
  "size": 1254302
}
```

This metadata is authenticated by GCM but **not encrypted** — it's readable by the `info` command without a password.

---

## Supported File Types

| Category | Extensions |
|----------|-----------|
| 📄 Documents | `.pdf` `.docx` `.doc` `.txt` `.xlsx` `.xls` `.csv` `.pptx` `.odt` |
| 🖼 Images | `.jpg` `.jpeg` `.png` `.gif` `.bmp` `.webp` `.svg` `.tiff` |
| 🎬 Videos | `.mp4` `.avi` `.mkv` `.mov` `.wmv` `.webm` `.flv` `.m4v` |
| 🎵 Audio | `.mp3` `.wav` `.flac` `.aac` `.ogg` `.m4a` |
| 📦 Archives | `.zip` `.tar` `.gz` `.rar` `.7z` |
| 💻 Code | `.py` `.js` `.html` `.css` `.json` `.xml` `.sh` |
| 🔒 Decrypt only | `.secf` |

> Any binary file can technically be encrypted regardless of extension. The tool validates supported types on the web interface but the CLI accepts any file.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Error (file not found, wrong password, corrupted file, bad arguments) |

Use exit codes in shell scripts:
```bash
python securefile_cli.py decrypt secret.secf -p "mypassword"
if [ $? -eq 0 ]; then
    echo "Decryption succeeded"
else
    echo "Decryption failed — wrong password or corrupted file"
fi
```

---

## Tips & Best Practices

**Use strong passwords**
Combine uppercase, lowercase, numbers, and symbols. Example: `Tr0ub4dor&3!`
The PBKDF2 stretching helps, but a strong password is still your first line of defense.

**Never pass passwords in production scripts via `-p`**
The password may appear in shell history (`~/.bash_history`). Use the interactive prompt or store passwords in environment variables:
```bash
export SF_PASS="MyStr0ng@Pass!"
python securefile_cli.py encrypt file.pdf -p "$SF_PASS"
```

**Back up your password**
There is no password recovery. A lost password means a permanently inaccessible file.

**Verify decryption after encrypting important files**
Before using `--delete-original`, always test that you can decrypt successfully:
```bash
python securefile_cli.py encrypt important.pdf
python securefile_cli.py decrypt important.secf  # Verify first
rm important.pdf                                  # Then delete manually
```

**Use `info` to verify a `.secf` file before decrypting**
```bash
python securefile_cli.py info mystery_file.secf
# Confirms the original filename and size before you enter a password
```

---

## Troubleshooting

### `❌ Missing dependency. Run: pip install cryptography`
```bash
pip install cryptography
# or
pip3 install cryptography
```

### `✖ Decryption failed! Wrong password or corrupted file.`
- Double-check the password (case-sensitive)
- Ensure the `.secf` file was not modified or partially transferred
- If the file was transferred, check for corruption (re-download/re-copy)

### `✖ File not found: filename.pdf`
- Check the file path is correct
- Use quotes around paths with spaces: `python securefile_cli.py encrypt "my file.pdf"`

### `✖ Only .secf files can be decrypted`
- You are trying to decrypt a non-encrypted file
- Only files previously encrypted by SecureFile (ending in `.secf`) can be decrypted

### Python version errors
```bash
# Use python3 explicitly if python maps to Python 2
python3 securefile_cli.py encrypt file.pdf
```

### Permission denied on Linux/macOS
```bash
chmod +x securefile_cli.py
./securefile_cli.py encrypt file.pdf
```

---

## Author

**Senthil Nathan**  
M.Sc. Cyber Forensic & Information Security  
Dr. MGR Education and Research Institute, Chennai

[![Portfolio](https://img.shields.io/badge/Portfolio-senthil.zeal.ninja-blue?style=flat&logo=Firefox)](https://senthil.zeal.ninja)
[![Email](https://img.shields.io/badge/Email-senthilnathans1730@gmail.com-red?style=flat&logo=gmail)](mailto:senthilnathans1730@gmail.com)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Senthil_Nathan-0077B5?style=flat&logo=linkedin)](https://www.linkedin.com/in/senthilnathan17092003)
[![Twitter](https://img.shields.io/badge/Twitter-@senthil1730-1DA1F2?style=flat&logo=twitter)](https://twitter.com/senthil1730)

---

## License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

*SecureFile CLI Manual · AES-256-GCM · PBKDF2-SHA256 · 600K Iterations*
