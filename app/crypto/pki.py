import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding

# --- Certificate & Key Loading ---

def load_pem_certificate(path):
    """Loads a PEM certificate from file."""
    with open(path, "rb") as f:
        cert_data = f.read()
    return x509.load_pem_x509_certificate(cert_data, default_backend())

def load_pem_private_key(path):
    """Loads a PEM private key from file."""
    with open(path, "rb") as f:
        key_data = f.read()
    return serialization.load_pem_private_key(key_data, password=None, backend=default_backend())

def serialize_certificate(cert):
    """Converts an x509.Certificate object to PEM bytes."""
    return cert.public_bytes(serialization.Encoding.PEM)

def deserialize_certificate(cert_bytes):
    """Converts PEM bytes to an x509.Certificate object."""
    return x509.load_pem_x509_certificate(cert_bytes, default_backend())

# --- PKI & Certificate Validation ---

def validate_certificate(cert_to_check, ca_cert):
    """
    Validates a certificate against a CA certificate.
    Checks signature, expiry, and issuer.
    """
    
    # 1. Check signature
    try:
        ca_cert.public_key().verify(
            cert_to_check.signature,
            cert_to_check.tbs_certificate_bytes,
            rsa_padding.PKCS1v15(),
            cert_to_check.signature_hash_algorithm,
        )
    except InvalidSignature:
        print("Validation failed: Invalid signature")
        return False, "BAD_CERT: Invalid signature"

    # 2. Check expiry (using UTC-aware properties)
    now = datetime.datetime.now(datetime.timezone.utc)
    if now < cert_to_check.not_valid_before_utc:
        print("Validation failed: Certificate not yet valid")
        return False, "BAD_CERT: Not yet valid"
    if now > cert_to_check.not_valid_after_utc:
        print("Validation failed: Certificate expired")
        return False, "BAD_CERT: Expired"

    # 3. Check issuer
    if cert_to_check.issuer != ca_cert.subject:
        print("Validation failed: Mismatched issuer")
        return False, "BAD_CERT: Mismatched issuer"

    print("Certificate validation successful.")
    return True, "Certificate valid"