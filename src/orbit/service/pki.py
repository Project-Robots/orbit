from asyncio.constants import SSL_HANDSHAKE_TIMEOUT
import ssl
import orbit.component.pki as pki
import uvicorn

class PKIService():
    def __init__(self, bind_address="0.0.0.0", port=8000):
        self.bind_address = bind_address
        self.port = port
        
    def run(self):
        """Start PKI/Certificate Authority API server using FastAPI."""
        uvicorn.run('orbit.component.pki:app', host=self.bind_address, port=self.port, log_level="debug", ssl_keyfile="/etc/orbit/ca/private_key.pem", ssl_certfile="/etc/orbit/ca/cacert.pem")