from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend

# --- DH Key Exchange Functions ---

# Use the static RFC 3526 parameters from your protocol.py
try:
    print("[Protocol] Using RFC 3526 2048-bit MODP group (static params)...")
    # RFC 3526 2048-bit MODP Group (Group 14) prime in hex
    _P_HEX = (
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
        "FFFFFFFFFFFFFFFF"
    )
    _P = int(_P_HEX, 16)
    _G = 2
    DH_PARAMS = dh.DHParameterNumbers(_P, _G).parameters(default_backend())
    print("[Protocol] DH parameters loaded.")
except Exception as _e:
    print(f"[Protocol] Failed to load static DH params ({_e}); generating instead...")
    DH_PARAMS = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    print("[Protocol] DH parameters generated.")


def dh_generate_key_pair():
    """Generates a new DH private and public key."""
    private_key = DH_PARAMS.generate_private_key()
    public_key = private_key.public_key()
    
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_bytes

def dh_compute_shared_secret(private_key, peer_public_bytes):
    """Computes the shared secret from our private key and peer's public key."""
    peer_public_key = serialization.load_pem_public_key(
        peer_public_bytes,
        backend=default_backend()
    )
    
    shared_secret = private_key.exchange(peer_public_key)
    return shared_secret

def derive_aes_key(shared_secret):
    """
    Derives a 16-byte AES key from the shared secret.
    K = Trunc16(SHA256(Ks))
    """
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(shared_secret)
    full_hash = hasher.finalize()
    
    return full_hash[:16]
