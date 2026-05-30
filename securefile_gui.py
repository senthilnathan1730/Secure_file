#!/usr/bin/env python3
"""
SecureFile GUI — AES-256-GCM Encryption Desktop App
Author: Senthil Nathan
Requires: pip install cryptography
"""

import os
import json
import hashlib
import secrets
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'cryptography'])
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Colors ─────────────────────────────────────────────────────────────────
BG       = '#030712'
SURFACE  = '#0a1020'
PANEL    = '#0d1b2a'
BORDER   = '#1a3a5c'
GLOW     = '#00f5c4'
BLUE     = '#0090ff'
DANGER   = '#ff3b5c'
WARN     = '#f5a623'
TEXT     = '#c8d8e8'
MUTED    = '#4a6080'
SUCCESS  = '#00e599'
WHITE    = '#ffffff'

# ── Crypto ─────────────────────────────────────────────────────────────────
def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600_000, 32)

def encrypt_file(src_path: Path, password: str, dest_path: Path, progress_cb=None):
    salt  = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    key   = derive_key(password, salt)

    if progress_cb: progress_cb(20, "Deriving key…")

    with open(src_path, 'rb') as f:
        plaintext = f.read()

    if progress_cb: progress_cb(45, "Reading file…")

    aad = json.dumps({
        "filename": src_path.name,
        "extension": src_path.suffix.lower(),
        "size": len(plaintext)
    }).encode()

    aesgcm = AESGCM(key)
    if progress_cb: progress_cb(60, "Encrypting…")
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    aad_len = len(aad).to_bytes(4, 'big')
    encrypted = salt + nonce + aad_len + aad + ciphertext

    with open(dest_path, 'wb') as f:
        f.write(encrypted)

    if progress_cb: progress_cb(100, "Done!")
    return len(plaintext), len(encrypted)

def decrypt_file(src_path: Path, password: str, dest_path: Path, progress_cb=None):
    with open(src_path, 'rb') as f:
        data = f.read()

    if len(data) < 48:
        raise ValueError("Invalid or corrupted file.")

    if progress_cb: progress_cb(20, "Parsing header…")
    offset = 0
    salt   = data[offset:offset+32]; offset += 32
    nonce  = data[offset:offset+12]; offset += 12
    aad_ln = int.from_bytes(data[offset:offset+4], 'big'); offset += 4
    aad    = data[offset:offset+aad_ln]; offset += aad_ln
    ct     = data[offset:]

    if progress_cb: progress_cb(40, "Deriving key…")
    key = derive_key(password, salt)

    if progress_cb: progress_cb(65, "Decrypting…")
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ct, aad)
    except Exception:
        raise ValueError("Wrong password or corrupted file.")

    meta = json.loads(aad.decode())

    with open(dest_path, 'wb') as f:
        f.write(plaintext)

    if progress_cb: progress_cb(100, "Done!")
    return meta, len(plaintext)

def fmt_size(b):
    for u in ['B','KB','MB','GB']:
        if b < 1024: return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} TB"

# ── Main App ───────────────────────────────────────────────────────────────
class SecureFileApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureFile — AES-256-GCM")
        self.root.geometry("900x680")
        self.root.configure(bg=BG)
        self.root.resizable(True, True)
        self.root.minsize(750, 580)

        self.selected_file = tk.StringVar()
        self.password      = tk.StringVar()
        self.mode          = tk.StringVar(value='encrypt')
        self.show_pw       = False

        self._build_ui()

    # ── UI Builder ──────────────────────────────────────────────────────────
    def _build_ui(self):
        # ── Header ──
        hdr = tk.Frame(self.root, bg=PANEL, pady=18)
        hdr.pack(fill='x')

        tk.Label(hdr, text="🔐  SecureFile", font=("Courier", 22, "bold"),
                 fg=WHITE, bg=PANEL).pack(side='left', padx=24)
        tk.Label(hdr, text="AES-256-GCM · PBKDF2-SHA256 · 600K ITERATIONS",
                 font=("Courier", 9), fg=GLOW, bg=PANEL).pack(side='left', padx=8)

        # Status dot
        self.status_dot = tk.Label(hdr, text="● SYSTEM ONLINE",
                                   font=("Courier", 8), fg=GLOW, bg=PANEL)
        self.status_dot.pack(side='right', padx=24)

        # ── Main Content ──
        content = tk.Frame(self.root, bg=BG)
        content.pack(fill='both', expand=True, padx=20, pady=16)

        # Left panel
        left = tk.Frame(content, bg=PANEL, bd=0, relief='flat',
                        highlightbackground=BORDER, highlightthickness=1)
        left.pack(side='left', fill='both', expand=True, padx=(0,12))

        # Right panel
        right = tk.Frame(content, bg=SURFACE, bd=0, relief='flat',
                         highlightbackground=BORDER, highlightthickness=1,
                         width=260)
        right.pack(side='right', fill='y')
        right.pack_propagate(False)

        self._build_left(left)
        self._build_right(right)

    def _build_left(self, parent):
        pad = {'padx': 22, 'pady': 6}

        # ── Mode Tabs ──
        tab_frame = tk.Frame(parent, bg=PANEL)
        tab_frame.pack(fill='x', padx=22, pady=(18,6))

        tk.Label(tab_frame, text="// OPERATION MODE",
                 font=("Courier", 8), fg=GLOW, bg=PANEL).pack(side='left')

        btn_frame = tk.Frame(parent, bg=SURFACE, bd=0,
                             highlightbackground=BORDER, highlightthickness=1)
        btn_frame.pack(fill='x', padx=22, pady=(0,12))

        self.enc_btn = tk.Button(btn_frame, text="🔒  ENCRYPT",
                                 font=("Courier", 10, "bold"),
                                 bg=GLOW, fg='#000', relief='flat',
                                 cursor='hand2', pady=10,
                                 command=lambda: self._switch_mode('encrypt'))
        self.enc_btn.pack(side='left', fill='x', expand=True, padx=4, pady=4)

        self.dec_btn = tk.Button(btn_frame, text="🔓  DECRYPT",
                                 font=("Courier", 10, "bold"),
                                 bg=SURFACE, fg=MUTED, relief='flat',
                                 cursor='hand2', pady=10,
                                 command=lambda: self._switch_mode('decrypt'))
        self.dec_btn.pack(side='left', fill='x', expand=True, padx=4, pady=4)

        # ── File Selection ──
        tk.Label(parent, text="// SELECT FILE",
                 font=("Courier", 8), fg=GLOW, bg=PANEL).pack(anchor='w', **pad)

        file_frame = tk.Frame(parent, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        file_frame.pack(fill='x', padx=22, pady=(0,8))

        self.file_lbl = tk.Label(file_frame, text="No file selected…",
                                 font=("Courier", 9), fg=MUTED, bg=SURFACE,
                                 wraplength=400, justify='left', pady=10, padx=12)
        self.file_lbl.pack(side='left', fill='x', expand=True)

        self.browse_btn = tk.Button(file_frame, text="Browse",
                                    font=("Courier", 9, "bold"),
                                    bg=BLUE, fg=WHITE, relief='flat',
                                    cursor='hand2', padx=16, pady=10,
                                    command=self._browse_file)
        self.browse_btn.pack(side='right', padx=4, pady=4)

        # File info
        self.file_info = tk.Label(parent, text="",
                                  font=("Courier", 8), fg=SUCCESS, bg=PANEL)
        self.file_info.pack(anchor='w', padx=22)

        # ── Password ──
        tk.Label(parent, text="// ENCRYPTION KEY / PASSWORD",
                 font=("Courier", 8), fg=GLOW, bg=PANEL).pack(anchor='w', **pad)

        pw_frame = tk.Frame(parent, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        pw_frame.pack(fill='x', padx=22, pady=(0,4))

        self.pw_entry = tk.Entry(pw_frame, textvariable=self.password,
                                 font=("Courier", 11), bg=SURFACE, fg=WHITE,
                                 insertbackground=GLOW, relief='flat',
                                 show='*', bd=0)
        self.pw_entry.pack(side='left', fill='x', expand=True, padx=12, pady=12)
        self.pw_entry.bind('<KeyRelease>', self._update_strength)

        self.eye_btn = tk.Button(pw_frame, text="👁", font=("Courier", 11),
                                 bg=SURFACE, fg=MUTED, relief='flat',
                                 cursor='hand2', padx=10,
                                 command=self._toggle_pw)
        self.eye_btn.pack(side='right', pady=6, padx=4)

        # Strength bar
        str_frame = tk.Frame(parent, bg=PANEL)
        str_frame.pack(fill='x', padx=22, pady=(0,12))

        self.str_bar = ttk.Progressbar(str_frame, length=300, mode='determinate',
                                        style='Strength.Horizontal.TProgressbar')
        self.str_bar.pack(side='left', fill='x', expand=True)

        self.str_lbl = tk.Label(str_frame, text="", font=("Courier", 8),
                                fg=MUTED, bg=PANEL, width=14, anchor='e')
        self.str_lbl.pack(side='right', padx=8)

        # Style strength bar
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Strength.Horizontal.TProgressbar',
                        troughcolor=BORDER, background=GLOW, thickness=4)

        # ── Progress ──
        tk.Label(parent, text="// PROGRESS",
                 font=("Courier", 8), fg=GLOW, bg=PANEL).pack(anchor='w', **pad)

        prog_frame = tk.Frame(parent, bg=PANEL)
        prog_frame.pack(fill='x', padx=22, pady=(0,4))

        self.progress = ttk.Progressbar(prog_frame, length=400, mode='determinate',
                                         style='Main.Horizontal.TProgressbar')
        self.progress.pack(side='left', fill='x', expand=True)
        style.configure('Main.Horizontal.TProgressbar',
                        troughcolor=BORDER, background=BLUE, thickness=6)

        self.prog_lbl = tk.Label(prog_frame, text="0%", font=("Courier", 8),
                                 fg=TEXT, bg=PANEL, width=6)
        self.prog_lbl.pack(side='right', padx=8)

        self.status_lbl = tk.Label(parent, text="Ready",
                                   font=("Courier", 8), fg=MUTED, bg=PANEL)
        self.status_lbl.pack(anchor='w', padx=22, pady=(0,12))

        # ── Log ──
        tk.Label(parent, text="// OPERATION LOG",
                 font=("Courier", 8), fg=GLOW, bg=PANEL).pack(anchor='w', **pad)

        log_frame = tk.Frame(parent, bg='#000',
                             highlightbackground=BORDER, highlightthickness=1)
        log_frame.pack(fill='x', padx=22, pady=(0,12))

        self.log_text = tk.Text(log_frame, font=("Courier", 8), bg='#000', fg=GLOW,
                                relief='flat', height=6, state='disabled',
                                insertbackground=GLOW)
        self.log_text.pack(fill='both', padx=8, pady=8)

        sb = tk.Scrollbar(log_frame, command=self.log_text.yview, bg=BORDER)
        sb.pack(side='right', fill='y')
        self.log_text.configure(yscrollcommand=sb.set)
        self.log_text.tag_configure('ok',   foreground=SUCCESS)
        self.log_text.tag_configure('err',  foreground=DANGER)
        self.log_text.tag_configure('warn', foreground=WARN)
        self.log_text.tag_configure('dim',  foreground=MUTED)

        # ── Action Button ──
        self.action_btn = tk.Button(parent, text="🔒  ENCRYPT FILE",
                                    font=("Courier", 13, "bold"),
                                    bg=GLOW, fg='#000', relief='flat',
                                    cursor='hand2', pady=16,
                                    command=self._run_action)
        self.action_btn.pack(fill='x', padx=22, pady=(0,18))

    def _build_right(self, parent):
        tk.Label(parent, text="// SECURITY SPECS",
                 font=("Courier", 8), fg=BLUE, bg=SURFACE).pack(anchor='w', padx=14, pady=(18,8))

        specs = [
            ("Cipher",      "AES-256-GCM",    GLOW),
            ("Key Size",    "256 bits",        SUCCESS),
            ("KDF",         "PBKDF2-SHA256",   BLUE),
            ("Iterations",  "600,000",         WARN),
            ("Salt",        "256 bits",        GLOW),
            ("Nonce/IV",    "96 bits",         SUCCESS),
            ("Auth Tag",    "128 bits",        BLUE),
            ("AAD",         "File metadata",   MUTED),
            ("Output",      ".secf format",    WARN),
        ]

        for label, val, color in specs:
            row = tk.Frame(parent, bg=SURFACE)
            row.pack(fill='x', padx=14, pady=2)
            tk.Label(row, text=f"● {label}", font=("Courier", 8),
                     fg=MUTED, bg=SURFACE, width=13, anchor='w').pack(side='left')
            tk.Label(row, text=val, font=("Courier", 8, "bold"),
                     fg=color, bg=SURFACE).pack(side='right')

        tk.Frame(parent, bg=BORDER, height=1).pack(fill='x', padx=14, pady=12)

        tk.Label(parent, text="// FORMATS",
                 font=("Courier", 8), fg=BLUE, bg=SURFACE).pack(anchor='w', padx=14, pady=(0,8))

        formats = [
            ("Documents", "PDF DOCX TXT XLSX",  '#60a5fa'),
            ("Images",    "JPG PNG GIF WEBP",    '#c084fc'),
            ("Videos",    "MP4 AVI MKV MOV",     '#fb923c'),
            ("Audio",     "MP3 WAV FLAC AAC",    '#4ade80'),
            ("Archives",  "ZIP TAR GZ RAR",      WARN),
        ]
        for cat, exts, color in formats:
            tk.Label(parent, text=cat, font=("Courier", 7), fg=MUTED, bg=SURFACE).pack(anchor='w', padx=14)
            tk.Label(parent, text=exts, font=("Courier", 8, "bold"), fg=color, bg=SURFACE,
                     wraplength=200, justify='left').pack(anchor='w', padx=14, pady=(0,4))

        tk.Frame(parent, bg=BORDER, height=1).pack(fill='x', padx=14, pady=8)

        # Warning
        warn_frame = tk.Frame(parent, bg='#1a1200',
                              highlightbackground='#4a3000', highlightthickness=1)
        warn_frame.pack(fill='x', padx=14, pady=(0,14))

        tk.Label(warn_frame, text="⚠ WARNING",
                 font=("Courier", 8, "bold"), fg=WARN, bg='#1a1200').pack(anchor='w', padx=10, pady=(8,2))
        tk.Label(warn_frame, text="Password is NEVER stored.\nLost password = lost file.\nStore it securely.",
                 font=("Courier", 7), fg=WARN, bg='#1a1200',
                 justify='left', wraplength=210).pack(anchor='w', padx=10, pady=(0,8))

    # ── Helpers ─────────────────────────────────────────────────────────────
    def _switch_mode(self, mode):
        self.mode.set(mode)
        if mode == 'encrypt':
            self.enc_btn.configure(bg=GLOW, fg='#000')
            self.dec_btn.configure(bg=SURFACE, fg=MUTED)
            self.action_btn.configure(text="🔒  ENCRYPT FILE", bg=GLOW, fg='#000')
            self.selected_file.set('')
            self.file_lbl.configure(text="No file selected…", fg=MUTED)
            self.file_info.configure(text="")
        else:
            self.dec_btn.configure(bg=DANGER, fg='#000')
            self.enc_btn.configure(bg=SURFACE, fg=MUTED)
            self.action_btn.configure(text="🔓  DECRYPT FILE", bg=DANGER, fg='#000')
            self.selected_file.set('')
            self.file_lbl.configure(text="Select a .secf file…", fg=MUTED)
            self.file_info.configure(text="")

    def _browse_file(self):
        if self.mode.get() == 'encrypt':
            filetypes = [
                ("All Files", "*.*"),
                ("Documents", "*.pdf *.docx *.txt *.xlsx *.csv"),
                ("Images", "*.jpg *.jpeg *.png *.gif *.webp *.bmp"),
                ("Videos", "*.mp4 *.avi *.mkv *.mov *.webm"),
                ("Audio", "*.mp3 *.wav *.flac *.aac *.ogg"),
            ]
        else:
            filetypes = [("SecureFile Encrypted", "*.secf"), ("All Files", "*.*")]

        path = filedialog.askopenfilename(filetypes=filetypes)
        if path:
            p = Path(path)
            self.selected_file.set(path)
            self.file_lbl.configure(text=p.name, fg=TEXT)
            size = p.stat().st_size
            self.file_info.configure(text=f"  Size: {fmt_size(size)}  |  Path: {p.parent}")

    def _toggle_pw(self):
        self.show_pw = not self.show_pw
        self.pw_entry.configure(show='' if self.show_pw else '*')

    def _update_strength(self, event=None):
        pw = self.password.get()
        score = 0
        if len(pw) >= 8:  score += 20
        if len(pw) >= 12: score += 20
        if any(c.isupper() for c in pw): score += 20
        if any(c.isdigit() for c in pw): score += 20
        if any(not c.isalnum() for c in pw): score += 20

        self.str_bar['value'] = score
        colors = {0:'',20:'red',40:'red',60:WARN,80:BLUE,100:SUCCESS}
        labels = {0:'—',20:'WEAK',40:'WEAK',60:'FAIR',80:'STRONG',100:'VERY STRONG'}
        self.str_lbl.configure(text=labels.get(score,''), fg=colors.get(score,MUTED))

        style = ttk.Style()
        c = {0:BORDER,20:DANGER,40:DANGER,60:WARN,80:BLUE,100:SUCCESS}.get(score,GLOW)
        style.configure('Strength.Horizontal.TProgressbar', background=c)

    def _log(self, msg, tag=''):
        self.log_text.configure(state='normal')
        self.log_text.insert('end', f"  › {msg}\n", tag)
        self.log_text.see('end')
        self.log_text.configure(state='disabled')

    def _clear_log(self):
        self.log_text.configure(state='normal')
        self.log_text.delete('1.0', 'end')
        self.log_text.configure(state='disabled')

    def _set_progress(self, val, status=''):
        self.progress['value'] = val
        self.prog_lbl.configure(text=f"{int(val)}%")
        if status:
            self.status_lbl.configure(text=status)
        self.root.update_idletasks()

    def _run_action(self):
        path = self.selected_file.get()
        pw   = self.password.get()

        if not path:
            messagebox.showerror("Error", "Please select a file first.")
            return
        if not pw or len(pw) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters.")
            return

        self.action_btn.configure(state='disabled', text="Processing…")
        self._clear_log()
        self._set_progress(0, "Starting…")

        mode = self.mode.get()
        if mode == 'encrypt':
            threading.Thread(target=self._do_encrypt, args=(path, pw), daemon=True).start()
        else:
            threading.Thread(target=self._do_decrypt, args=(path, pw), daemon=True).start()

    def _do_encrypt(self, path, pw):
        src = Path(path)
        try:
            self._log(f"Source: {src.name}")
            self._log(f"Size: {fmt_size(src.stat().st_size)}")
            self._log("Generating 256-bit salt + 96-bit nonce…")

            dest = filedialog.asksaveasfilename(
                defaultextension=".secf",
                initialfile=src.stem + ".secf",
                filetypes=[("SecureFile", "*.secf")]
            )
            if not dest:
                self.root.after(0, self._reset_btn)
                return

            dest_path = Path(dest)

            def cb(pct, msg):
                self.root.after(0, self._set_progress, pct, msg)
                self.root.after(0, self._log, msg)

            orig_sz, enc_sz = encrypt_file(src, pw, dest_path, cb)

            self.root.after(0, self._log, f"Encrypted: {dest_path.name}", 'ok')
            self.root.after(0, self._log, f"Original: {fmt_size(orig_sz)} → Encrypted: {fmt_size(enc_sz)}", 'ok')
            self.root.after(0, self._log, "GCM auth tag embedded (tamper-proof)", 'ok')

            self.root.after(0, messagebox.showinfo, "Success",
                f"✅ Encryption complete!\n\nFile: {dest_path.name}\nSize: {fmt_size(enc_sz)}\n\nAlgorithm: AES-256-GCM\nKDF: PBKDF2-SHA256 (600K iterations)")
        except Exception as e:
            self.root.after(0, self._log, f"ERROR: {e}", 'err')
            self.root.after(0, messagebox.showerror, "Error", str(e))
        finally:
            self.root.after(0, self._reset_btn)

    def _do_decrypt(self, path, pw):
        src = Path(path)
        try:
            self._log(f"Source: {src.name}")
            self._log("Parsing cryptographic header…")

            dest = filedialog.asksaveasfilename(
                title="Save Decrypted File As",
                initialfile="decrypted_file"
            )
            if not dest:
                self.root.after(0, self._reset_btn)
                return

            dest_path = Path(dest)

            def cb(pct, msg):
                self.root.after(0, self._set_progress, pct, msg)
                self.root.after(0, self._log, msg)

            meta, dec_sz = decrypt_file(src, pw, dest_path, cb)

            self.root.after(0, self._log, f"Decrypted: {dest_path.name}", 'ok')
            self.root.after(0, self._log, f"Original name: {meta['filename']}", 'ok')
            self.root.after(0, self._log, f"Size: {fmt_size(dec_sz)}", 'ok')
            self.root.after(0, self._log, "GCM authentication verified ✓", 'ok')

            self.root.after(0, messagebox.showinfo, "Success",
                f"✅ Decryption complete!\n\nFile: {dest_path.name}\nOriginal: {meta['filename']}\nSize: {fmt_size(dec_sz)}\n\nIntegrity: GCM Auth Verified ✓")
        except ValueError as e:
            self.root.after(0, self._log, f"ERROR: {e}", 'err')
            self.root.after(0, messagebox.showerror, "Decryption Failed", str(e))
        except Exception as e:
            self.root.after(0, self._log, f"ERROR: {e}", 'err')
            self.root.after(0, messagebox.showerror, "Error", str(e))
        finally:
            self.root.after(0, self._reset_btn)

    def _reset_btn(self):
        mode = self.mode.get()
        txt = "🔒  ENCRYPT FILE" if mode == 'encrypt' else "🔓  DECRYPT FILE"
        bg  = GLOW if mode == 'encrypt' else DANGER
        self.action_btn.configure(state='normal', text=txt, bg=bg)

# ── Run ────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    root = tk.Tk()
    app = SecureFileApp(root)
    root.mainloop()
