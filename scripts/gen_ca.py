import datetime
import argparse
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_ca(name):
    print(f"Generating CA private key for '{name}'...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    print("Saving CA private key to certs/ca_key.pem...")
    with open("certs/ca_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])

    builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    )

    certificate = builder.sign(private_key, hashes.SHA256())

    print("Saving CA certificate to certs/ca_cert.pem...")
    with open("certs/ca_cert.pem", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print("CA generation complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Root CA")
    parser.add_argument(
        '--name', 
        type=str, 
        default="SecureChat Root CA", 
        help="Common Name for the Root CA"
    )
    args = parser.parse_args()
    
    generate_ca(args.name)