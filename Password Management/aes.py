from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
import base64
import os

# Key Derivation Function (KDF) to generate a strong AES key
def derive_key(password, salt=b'somesalt', key_size=32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_size,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# AES Encryption
def encrypt_aes(password, secret):
    key = derive_key(secret)  # Use a secret phrase to derive the key
    iv = os.urandom(16)  # Generate a random IV
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(password.encode()) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_password = encryptor.update(padded_data) + encryptor.finalize()
    
    return base64.b64encode(iv + encrypted_password).decode()

# AES Decryption
def decrypt_aes(encrypted_password, secret):
    key = derive_key(secret)  # Use the same secret phrase for key derivation
    encrypted_password = base64.b64decode(encrypted_password)
    
    iv = encrypted_password[:16]  # Extract IV
    ciphertext = encrypted_password[16:]  # Extract actual encrypted data
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    
    return decrypted_data.decode()

