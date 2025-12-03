import datetime
import sys
import argparse
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def load_ca():
    """Loads the CA's private key and certificate."""
    try:
        with open("certs/ca_key.pem", "rb") as f:
            ca_private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )
        with open("certs/ca_cert.pem", "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        return ca_private_key, ca_cert
    except FileNotFoundError:
        print("Error: CA key or certificate not found.")
        print("Please run 'python scripts/gen_ca.py' first.")
        sys.exit(1)

def generate_entity_cert(common_name, output_path, ca_key, ca_cert):
    """
    Generates a new private key and a certificate for an entity.
    """
    print(f"Generating key and certificate for '{common_name}'...")
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    key_path = f"{output_path}_key.pem"
    print(f"Saving private key to {key_path}...")
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat Entity"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    )
    
    # Add Subject Alternative Name (SAN) for 'localhost' if it's the server
    if common_name == "server.local":
         builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(u"server.local"),
                x509.DNSName(u"localhost")
            ]),
            critical=False,
        )

    certificate = builder.sign(ca_key, hashes.SHA256())

    cert_path = f"{output_path}_cert.pem"
    print(f"Saving certificate to {cert_path}...")
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print(f"Successfully generated key/cert for '{common_name}'.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Client/Server Certificate")
    parser.add_argument('--cn', type=str, required=True, help="Common Name for the certificate (e.g., server.local)")
    parser.add_argument('--out', type=str, required=True, help="Output path prefix (e.g., certs/server)")
    args = parser.parse_args()

    ca_private_key, ca_cert = load_ca()
    generate_entity_cert(args.cn, args.out, ca_private_key, ca_cert)