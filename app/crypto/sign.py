from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.backends import default_backend
import base64

def sign_message(private_key, data):
    """
    Signs data using RSA-PSS with SHA-256.
    The assignment specifies PKCS#1 v1.5, which we will use.
    """
    # Per assignment spec[cite: 207], use PKCS#1 v1.5 padding
    signature = private_key.sign(
        data,
        rsa_padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(public_key, data, b64_signature):
    """
    Verifies an RSA-PSS SHA-256 signature.
    """
    try:
        signature = base64.b64decode(b64_signature)
        
        public_key.verify(
            signature,
            data,
            rsa_padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"[Signature] Verification failed: {e}")
        return False

def get_message_hash(seqno, timestamp, ciphertext):
    """
    Computes the hash h = SHA256(seqno || timestamp || ciphertext)
    [cite: 206]
    """
    # Ensure components are bytes
    seqno_bytes = str(seqno).encode('utf-8')
    ts_bytes = str(timestamp).encode('utf-8')
    ct_bytes = ciphertext.encode('utf-8') # ciphertext is already b64 string
    
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(seqno_bytes)
    hasher.update(ts_bytes)
    hasher.update(ct_bytes)
    return hasher.finalize()