import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

# --- AES Encryption/Decryption Functions ---

def aes_encrypt(key, plaintext):
    """
    Encrypts plaintext using AES-128 CBC with PKCS#7 padding.
    Returns: Base64-encoded string of (iv + ciphertext)
    """
    # 1. Generate a random 16-byte IV (Initialization Vector)
    iv = os.urandom(16)
    
    # 2. Create PKCS#7 padding
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    
    # 3. Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # 4. Return Base64-encoded (IV + Ciphertext)
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def aes_decrypt(key, b64_ciphertext):
    """
    Decrypts a Base64-encoded (IV + ciphertext) string.
    """
    try:
        # 1. Decode from Base64
        iv_plus_ciphertext = base64.b64decode(b64_ciphertext)
        
        # 2. Extract IV and ciphertext
        iv = iv_plus_ciphertext[:16]
        ciphertext = iv_plus_ciphertext[16:]
        
        # 3. Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # 4. Remove PKCS#7 padding
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext.decode('utf-8')
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None