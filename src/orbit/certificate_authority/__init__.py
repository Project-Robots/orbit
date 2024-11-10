from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import pytz
from pydantic import BaseModel, Field
import os

class CertificateAuthority(BaseModel):
  country: str = Field(default="US", description="Country Name (2 letter code)")
  state: str = Field(default="California", description="State or Province Name (full name)")
  locality: str = Field(default="San Francisco", description="Locality Name (eg, city)")
  organization: str = Field(default="Orbit Inc.", description="Organization Name (eg, company)")
  organizational_unit: str = Field(default="IT Department", description="Organizational Unit (eg, section)")
  common_name: str = Field(default="orbit.local", description="Common Name (e.g., server FQDN or YOUR name)")
  alt_names: list[str] = Field(default_factory=lambda: ["localhost", "orbit.local"], description="Subject Alternative Names")

  private_key_path: str = "/etc/orbit/ca/private_key.pem"
  certificate_path: str = "/etc/orbit/ca/cacert.pem"
 
  _private_key: rsa.RSAPrivateKey = None
  _certificate: x509.Certificate = None
  
  def generate_key_and_cert(self):
    # Check if CA private key and certificate already exist
    if os.path.exists(self.private_key_path) and os.path.exists(self.certificate_path):
        print("CA private key and certificate already exist.")
        return

    # Generate private key
    self._private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Generate a self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, self.country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, self.locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.organizational_unit),
        x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
    ])

    # Add Subject Alternative Names (SAN)
    san = x509.SubjectAlternativeName([
        x509.DNSName(name) for name in self.alt_names
    ])

    # Build the certificate
    self._certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(self._private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(pytz.timezone('UTC')))
        .not_valid_after(datetime.now(pytz.timezone('UTC')) + timedelta(days=3650))  # 10 years validity
        .sign(self._private_key, hashes.SHA256(), default_backend())
    )

    # Save the private key and certificate
    os.makedirs(os.path.dirname(self.private_key_path), exist_ok=True)

    with open(self.private_key_path, "wb") as f:
        f.write(
            self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(self.certificate_path, "wb") as f:
        f.write(
            self._certificate.public_bytes(serialization.Encoding.PEM)
        )

    print(f"CA private key and certificate generated at {self.private_key_path} and {self.certificate_path}.")
    
  def sign_csr(self, csr: x509.CertificateSigningRequest) -> x509.Certificate:
    
    """Signs a certificate signing request (CSR) and returns the signed certificate."""
    certificate = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(self._certificate.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.now(datetime.timezone.utc) + timedelta(days=3650))  # 10 years validity
        .add_extension(
          x509.BasicConstraints(ca=False, path_length=0),
          critical=True,
        )
        .sign(self._private_key, hashes.SHA256(), default_backend())
    )

    return certificate
  
  def verify_certificate(self, certificate):
    # Load the CA certificate
    with open(self.certificate_path, "rb") as f:
        self.certificate = x509.load_pem_x509_certificate(f.read(), default_backend())

    # Verify the certificate
    try:
        self.certificate.public_key().verify(
            certificate,
            signature=certificate.signature,
            padding=padding.PKCS1v15(),
            algorithm=hashes.SHA256()
        )
        return True
    except:
        return False