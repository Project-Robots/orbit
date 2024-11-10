from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
import base64

from socket import gethostname, getfqdn

from orbit.certificate_authority import CertificateAuthority # This is the class that is used to create a CA.

app = FastAPI()

ca = CertificateAuthority(
  country="US",
  state="California",
  locality="Placentia",
  organization="Thought Parameters LLC",
  organizational_unit="Engineering",
  common_name="Orbit Certificate Authority"
)

ca.generate_key_and_cert()

class CSRRequest(BaseModel):
  """Request body for CSR generation."""
  csr: str

@app.get("/")
def root():
  return JSONResponse({"message": "Orbit Server - Public Key Infrastructure"}, status_code=200)

@app.get("/pki/ca/certificate")
def get_ca_certificate():
  """Returns the CA certificate."""
  return JSONResponse({"message": "Orbit Server - Public Key Infrastructure"}, status_code=200)

@app.post("/pki/ca/sign-certificate")
def sign_certificate(request: CSRRequest):
  
  try:
    """Signs a certificate."""
    csr_data = base64.b64decode(request.csr.encode())
    csr = x509.load_pem_x509_csr(csr_data)
    
    # Verify CSR validity
    if not csr.is_signature_valid:
      raise HTTPException(status_code=400, detail="Invalid CSR signature.")
    
    # Sign the CSR with the CA
    signed_cert = ca.sign_csr(csr)
    
    # Return the signed certificate in PEM format, encoded in Base64
    signed_cert_pem = signed_cert.public_bytes(serialization.Encoding.PEM)
    signed_cert_base64 = base64.b64encode(signed_cert_pem).decode()
    
    return JSONResponse({"certificate": signed_cert_base64}, status_code=200)
  except Exception as e:
    raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
  