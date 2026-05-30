#!/usr/bin/env python3
"""
SecureFile CLI — AES-256-GCM Encryption Tool
Author: Senthil Nathan
Usage: python securefile_cli.py encrypt|decrypt <file> [options]
"""

import os
import sys
import json
import base64
import hashlib
import secrets
import getpass
import argparse
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("❌ Missing dependency. Run: pip install cryptography")
    sys.exit(1)

# ── Colors (ANSI) ──────────────────────────────────────────────────────────
class C:
    RESET  = '\033[0m'
    BOLD   = '\033[1m'
    GREEN  = '\033[92m'
    CYAN   = '\033[96m'
    YELLOW = '\033[93m'
    RED    = '\033[91m'
    MAGENTA= '\033[95m'
    DIM    = '\033[2m'
    BLUE   = '\033[94m'

def banner():
    print(f"""
{C.CYAN}{C.BOLD}
  ╔═══════════════════════════════════════════════╗
  ║   🔐  SecureFile — AES-256-GCM CLI Tool       ║
  ║   Encryption: AES-256-GCM                     ║
  ║   KDF: PBKDF2-HMAC-SHA256 (600,000 iters)     ║
  ║   Author: Senthil Nathan                      ║
  ╚═══════════════════════════════════════════════╝
{C.RESET}""")

def fmt_size(b):
    for u in ['B','KB','MB','GB']:
        if b < 1024: return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} TB"

def log(msg, level='info'):
    icons = {'info':'►','ok':'✔','warn':'⚠','err':'✖','step':'◆'}
    colors = {'info':C.CYAN,'ok':C.GREEN,'warn':C.YELLOW,'err':C.RED,'step':C.MAGENTA}
    icon  = icons.get(level,'►')
    color = colors.get(level, C.CYAN)
    print(f"  {color}{icon}{C.RESET}  {msg}")

def derive_key(password: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256, 600k iterations → 256-bit key."""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600_000, 32)

# ── Encrypt ────────────────────────────────────────────────────────────────
def cmd_encrypt(args):
    src = Path(args.file)
    if not src.exists():
        log(f"File not found: {src}", 'err'); sys.exit(1)

    # Get password
    if args.password:
        password = args.password
    else:
        password = getpass.getpass(f"  {C.CYAN}Password:{C.RESET} ")
        confirm  = getpass.getpass(f"  {C.CYAN}Confirm :{C.RESET} ")
        if password != confirm:
            log("Passwords do not match.", 'err'); sys.exit(1)

    if len(password) < 6:
        log("Password must be at least 6 characters.", 'err'); sys.exit(1)

    out_path = Path(args.output) if args.output else src.with_suffix('.secf')

    print()
    log(f"Source file  : {src.name} ({fmt_size(src.stat().st_size)})", 'step')
    log(f"Output file  : {out_path.name}", 'step')
    log("Algorithm    : AES-256-GCM", 'step')
    log("KDF          : PBKDF2-HMAC-SHA256 (600,000 iterations)", 'step')
    print()

    log("Generating cryptographic parameters…", 'info')
    salt  = secrets.token_bytes(32)   # 256-bit salt
    nonce = secrets.token_bytes(12)   # 96-bit nonce

    log("Deriving encryption key…", 'info')
    key = derive_key(password, salt)

    log(f"Reading {fmt_size(src.stat().st_size)}…", 'info')
    with open(src, 'rb') as f:
        plaintext = f.read()

    aad = json.dumps({
        "filename": src.name,
        "extension": src.suffix.lower(),
        "size": len(plaintext)
    }).encode()

    log("Encrypting with AES-256-GCM…", 'info')
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    aad_len = len(aad).to_bytes(4, 'big')
    encrypted_data = salt + nonce + aad_len + aad + ciphertext

    with open(out_path, 'wb') as f:
        f.write(encrypted_data)

    ratio = len(encrypted_data) / len(plaintext) * 100
    print()
    log("Encryption complete!", 'ok')
    log(f"Output        : {out_path}", 'ok')
    log(f"Original size : {fmt_size(len(plaintext))}", 'ok')
    log(f"Encrypted size: {fmt_size(len(encrypted_data))} ({ratio:.1f}% of original)", 'ok')
    log("GCM auth tag  : Embedded (tamper-proof)", 'ok')
    print()

    if args.delete_original:
        src.unlink()
        log(f"Original file deleted: {src.name}", 'warn')

# ── Decrypt ────────────────────────────────────────────────────────────────
def cmd_decrypt(args):
    src = Path(args.file)
    if not src.exists():
        log(f"File not found: {src}", 'err'); sys.exit(1)
    if src.suffix.lower() != '.secf':
        log("Only .secf files can be decrypted.", 'err'); sys.exit(1)

    password = args.password if args.password else getpass.getpass(f"  {C.CYAN}Password:{C.RESET} ")

    print()
    log(f"Encrypted file: {src.name} ({fmt_size(src.stat().st_size)})", 'step')
    log("Algorithm     : AES-256-GCM", 'step')
    print()

    log("Reading encrypted file…", 'info')
    with open(src, 'rb') as f:
        data = f.read()

    if len(data) < 48:
        log("Invalid or corrupted file.", 'err'); sys.exit(1)

    log("Parsing cryptographic header…", 'info')
    offset = 0
    salt   = data[offset:offset+32]; offset += 32
    nonce  = data[offset:offset+12]; offset += 12
    aad_ln = int.from_bytes(data[offset:offset+4], 'big'); offset += 4
    aad    = data[offset:offset+aad_ln]; offset += aad_ln
    ct     = data[offset:]

    log("Deriving decryption key…", 'info')
    key = derive_key(password, salt)

    log("Decrypting and verifying integrity…", 'info')
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ct, aad)
    except Exception:
        log("Decryption failed! Wrong password or corrupted file.", 'err')
        sys.exit(1)

    meta = json.loads(aad.decode())
    orig_name = meta["filename"]
    orig_ext  = meta["extension"]

    out_path = Path(args.output) if args.output else src.parent / orig_name

    # Avoid overwriting
    if out_path.exists() and not args.overwrite:
        stem = out_path.stem
        for i in range(1, 999):
            candidate = out_path.parent / f"{stem}_{i}{orig_ext}"
            if not candidate.exists():
                out_path = candidate; break

    with open(out_path, 'wb') as f:
        f.write(plaintext)

    print()
    log("Decryption complete!", 'ok')
    log(f"Output file   : {out_path}", 'ok')
    log(f"Original name : {orig_name}", 'ok')
    log(f"File size     : {fmt_size(len(plaintext))}", 'ok')
    log("Integrity     : GCM authentication PASSED ✓", 'ok')
    print()

# ── Info ───────────────────────────────────────────────────────────────────
def cmd_info(args):
    src = Path(args.file)
    if not src.exists():
        log(f"File not found: {src}", 'err'); sys.exit(1)
    if src.suffix.lower() != '.secf':
        log("Only .secf files are supported.", 'err'); sys.exit(1)

    with open(src, 'rb') as f:
        data = f.read()

    if len(data) < 48:
        log("Invalid or corrupted file.", 'err'); sys.exit(1)

    aad_ln = int.from_bytes(data[44:48], 'big')
    aad    = data[48:48+aad_ln]
    meta   = json.loads(aad.decode())

    print()
    log(f"File         : {src.name}", 'info')
    log(f"Encrypted sz : {fmt_size(src.stat().st_size)}", 'info')
    log(f"Original name: {meta['filename']}", 'info')
    log(f"Original ext : {meta['extension']}", 'info')
    log(f"Original size: {fmt_size(meta['size'])}", 'info')
    log("Algorithm    : AES-256-GCM", 'info')
    log("KDF          : PBKDF2-HMAC-SHA256 (600,000 iters)", 'info')
    log("Salt         : 256-bit (embedded)", 'info')
    log("Nonce        : 96-bit (embedded)", 'info')
    log("Auth Tag     : 128-bit GCM tag (embedded)", 'info')
    print()

# ── Main ───────────────────────────────────────────────────────────────────
def main():
    banner()
    parser = argparse.ArgumentParser(
        prog='securefile',
        description='SecureFile — AES-256-GCM File Encryption CLI'
    )
    sub = parser.add_subparsers(dest='command', required=True)

    # Encrypt
    p_enc = sub.add_parser('encrypt', help='Encrypt a file')
    p_enc.add_argument('file', help='File to encrypt')
    p_enc.add_argument('-o', '--output', help='Output .secf path')
    p_enc.add_argument('-p', '--password', help='Password (or will prompt)')
    p_enc.add_argument('--delete-original', action='store_true', help='Delete original after encryption')

    # Decrypt
    p_dec = sub.add_parser('decrypt', help='Decrypt a .secf file')
    p_dec.add_argument('file', help='.secf file to decrypt')
    p_dec.add_argument('-o', '--output', help='Output file path')
    p_dec.add_argument('-p', '--password', help='Password (or will prompt)')
    p_dec.add_argument('--overwrite', action='store_true', help='Overwrite if output exists')

    # Info
    p_inf = sub.add_parser('info', help='Show metadata of a .secf file')
    p_inf.add_argument('file', help='.secf file to inspect')

    args = parser.parse_args()

    if args.command == 'encrypt':   cmd_encrypt(args)
    elif args.command == 'decrypt': cmd_decrypt(args)
    elif args.command == 'info':    cmd_info(args)

if __name__ == '__main__':
    main()
