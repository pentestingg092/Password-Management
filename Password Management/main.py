import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

THEMES = {
    "dark": {
        "bg": "#000000",
        "fg": "#00FF00",
        "button_bg": "#003300",
        "button_fg": "#00FF00",
        "text_bg": "#002200",
        "text_fg": "#00FF00",
        "highlight": "#FF00FF",
        "font": ("Fixedsys", 12),
        "heading_font": ("Fixedsys", 18, "bold")
    },
    "light": {
        "bg": "#C0C0C0",
        "fg": "#000000",
        "button_bg": "#808080",
        "button_fg": "#000080",
        "text_bg": "#FFFFFF",
        "text_fg": "#000000",
        "highlight": "#800000",
        "font": ("MS Sans Serif", 12),
        "heading_font": ("MS Sans Serif", 18, "bold")
    }
}

current_theme = "dark"

def set_theme(theme_name):
    global current_theme
    current_theme = theme_name
    theme = THEMES[theme_name]
    root.config(bg=theme["bg"])
    for widget in root.winfo_children():
        apply_theme(widget, theme)

def apply_theme(widget, theme):
    if isinstance(widget, tk.Frame):
        widget.config(bg=theme["bg"])
    elif isinstance(widget, tk.Label):
        widget.config(bg=theme["bg"], fg=theme["fg"], font=theme["font"])
    elif isinstance(widget, tk.Button):
        widget.config(
            bg=theme["button_bg"],
            fg=theme["button_fg"],
            font=theme["font"],
            relief="raised",
            borderwidth=3,
            activebackground=theme["highlight"]
        )
    elif isinstance(widget, (tk.Entry, tk.Text)):
        widget.config(
            bg=theme["text_bg"],
            fg=theme["text_fg"],
            insertbackground=theme["fg"],
            font=theme["font"],
            relief="sunken",
            borderwidth=2
        )
    for child in widget.winfo_children():
        apply_theme(child, theme)

def generate_aes_password(password):
    key = password.encode('utf-8')
    key = key.ljust(32, b'\0')[:32]
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(password.encode('utf-8')) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_password = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_password.hex()

def hash_password(password):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(password.encode('utf-8'))
    return digest.finalize().hex()

def check_password_strength(password):
    if len(password) < 8: return "Weak"
    elif len(password) < 12: return "Moderate"
    else: return "Strong"

def generate_chacha20_password(password):
    key = password.encode('utf-8').ljust(32, b'\0')[:32]
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_password = encryptor.update(password.encode('utf-8')) + encryptor.finalize()
    return encrypted_password.hex(), nonce.hex()

def decrypt_chacha20_password(encrypted_password_hex, nonce_hex, password):
    key = password.encode('utf-8')[:32]
    nonce = bytes.fromhex(nonce_hex)
    encrypted_password = bytes.fromhex(encrypted_password_hex)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_password) + decryptor.finalize().decode('utf-8')

def create_header():
    header_frame = tk.Frame(root, bg=THEMES[current_theme]["bg"])
    tk.Label(
        header_frame,
        text="▓▒░  PASSWORD MANAGER ░▒▓",
        font=THEMES[current_theme]["heading_font"],
        fg=THEMES[current_theme]["highlight"],
        bg=THEMES[current_theme]["bg"]
    ).pack(pady=10)
    
    tk.Button(
        header_frame,
        text="◑ Switch Theme",
        command=lambda: set_theme("light" if current_theme == "dark" else "dark"),
        font=THEMES[current_theme]["font"]
    ).pack(pady=5)
    
    return header_frame

def show_password_generator():
    clear_content()
    frame = tk.Frame(root, bg=THEMES[current_theme]["bg"])
    frame.pack(fill=tk.BOTH, expand=True)
    
    tk.Label(frame, text="Password:").pack(pady=5)
    password_entry = tk.Entry(frame, width=40, show="*")
    password_entry.pack(pady=5)
    
    result_text = tk.Text(frame, height=4, width=40)
    result_text.pack(pady=10)
    
    def generate():
        password = password_entry.get()
        if password:
            encrypted = generate_aes_password(password)
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, encrypted)
        else:
            messagebox.showerror("Error", "Enter a password!", parent=frame)
    
    tk.Button(
        frame,
        text="Generate AES Password",
        command=generate
    ).pack(pady=5)
    
    tk.Button(
        frame,
        text="Back",
        command=show_homepage
    ).pack(pady=10)

def show_hashing():
    clear_content()
    frame = tk.Frame(root, bg=THEMES[current_theme]["bg"])
    frame.pack(fill=tk.BOTH, expand=True)
    
    tk.Label(frame, text="Password:").pack(pady=5)
    password_entry = tk.Entry(frame, width=40, show="*")
    password_entry.pack(pady=5)
    
    result_text = tk.Text(frame, height=4, width=40)
    result_text.pack(pady=10)
    
    def hash_pw():
        password = password_entry.get()
        if password:
            hashed = hash_password(password)
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, hashed)
        else:
            messagebox.showerror("Error", "Enter a password!", parent=frame)
    
    tk.Button(
        frame,
        text="Generate Hash",
        command=hash_pw
    ).pack(pady=5)
    
    tk.Button(
        frame,
        text="Back",
        command=show_homepage
    ).pack(pady=10)

def show_chacha20():
    clear_content()
    frame = tk.Frame(root, bg=THEMES[current_theme]["bg"])
    frame.pack(fill=tk.BOTH, expand=True)
    
    tk.Label(frame, text="Password:").pack(pady=5)
    password_entry = tk.Entry(frame, width=40, show="*")
    password_entry.pack(pady=5)
    
    result_text = tk.Text(frame, height=4, width=40)
    nonce_text = tk.Text(frame, height=2, width=40)
    result_text.pack(pady=5)
    nonce_text.pack(pady=5)
    
    def encrypt():
        password = password_entry.get()
        if password:
            encrypted, nonce = generate_chacha20_password(password)
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, encrypted)
            nonce_text.delete(1.0, tk.END)
            nonce_text.insert(tk.END, nonce)
        else:
            messagebox.showerror("Error", "Enter a password!", parent=frame)
    
    tk.Button(
        frame,
        text="Encrypt with ChaCha20",
        command=encrypt
    ).pack(pady=5)
    
    tk.Button(
        frame,
        text="Back",
        command=show_homepage
    ).pack(pady=10)

def show_strength_checker():
    clear_content()
    frame = tk.Frame(root, bg=THEMES[current_theme]["bg"])
    frame.pack(fill=tk.BOTH, expand=True)
    
    tk.Label(frame, text="Password:").pack(pady=5)
    password_entry = tk.Entry(frame, width=40, show="*")
    password_entry.pack(pady=5)
    
    def check():
        password = password_entry.get()
        if password:
            strength = check_password_strength(password)
            messagebox.showinfo("Strength", f"Password Strength: {strength}", parent=frame)
        else:
            messagebox.showerror("Error", "Enter a password!", parent=frame)
    
    tk.Button(
        frame,
        text="Check Strength",
        command=check
    ).pack(pady=10)
    
    tk.Button(
        frame,
        text="Back",
        command=show_homepage
    ).pack(pady=10)

def show_homepage():
    clear_content()
    header.pack(fill=tk.X)
    frame = tk.Frame(root, bg=THEMES[current_theme]["bg"])
    frame.pack(fill=tk.BOTH, expand=True)
    
    buttons = [
        ("AES Password Generator", show_password_generator),
        ("SHA-256 Hashing", show_hashing),
        ("ChaCha20 Encryption", show_chacha20),
        ("Password Strength Checker", show_strength_checker)
    ]
    
    for text, command in buttons:
        tk.Button(
            frame,
            text=text,
            command=command,
            width=25
        ).pack(pady=8)

def clear_content():
    for widget in root.winfo_children():
        if widget not in [header]:
            widget.pack_forget()

root = tk.Tk()
root.title("Password Management")
root.geometry("800x600")

header = create_header()
set_theme(current_theme)
show_homepage()

root.mainloop()