import json
import os
import subprocess
import time
import uuid
from typing import Optional, Union

import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class StepCaClient:
    """Client for interacting with step-ca REST API and managing certificate issuance."""

    def __init__(
        self,
        ca_url: str = "https://127.0.0.1:9000",
        domain: str = "int.spoutin.org",
        provisioner_name: str = "admin@int.spoutin.org",
        provisioner_key_path: str = "/etc/step-ca/secrets/provisioner_key.json",
        provisioner_password: str = "",
        root_cert_path: str = "/etc/step-ca/certs/root_ca.crt",
        intermediate_cert_path: str = "/etc/step-ca/certs/intermediate_ca.crt",
        verify_ssl: Union[bool, str] = False,
    ):
        self.ca_url = ca_url.rstrip("/")
        self.domain = domain
        self.provisioner_name = provisioner_name
        self.provisioner_key_path = provisioner_key_path
        self.provisioner_password = provisioner_password
        self.root_cert_path = root_cert_path
        self.intermediate_cert_path = intermediate_cert_path
        self.verify_ssl = verify_ssl

        self.session = requests.Session()
        self.session.trust_env = False

    def generate_key_and_csr(self, common_name: str) -> tuple[rsa.RSAPrivateKey, bytes]:
        """Generates an RSA 2048-bit key and corresponding CSR in-memory."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        dns_names = [common_name]
        if self.domain and not common_name.endswith(f".{self.domain}"):
            dns_names.append(f"{common_name}.{self.domain}")

        san_extensions = [x509.DNSName(name) for name in dns_names]

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)])
            )
            .add_extension(
                x509.SubjectAlternativeName(san_extensions),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        return private_key, csr_pem

    def generate_provisioner_token(self, common_name: str) -> str:
        """Generates a short-lived one-time token (JWT) for the step-ca provisioner."""
        sans = [common_name]
        if self.domain and not common_name.endswith(f".{self.domain}"):
            sans.append(f"{common_name}.{self.domain}")

        # If step CLI is available on the system, we can mint the token directly
        cmd = [
            "step",
            "ca",
            "token",
            common_name,
            f"--ca-url={self.ca_url}",
            f"--provisioner={self.provisioner_name}",
        ]
        if os.path.exists(self.root_cert_path):
            cmd.append(f"--root={self.root_cert_path}")
        for san in sans:
            cmd.append(f"--san={san}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            return result.stdout.strip()
        except Exception as e:
            raise RuntimeError(
                f"Failed to generate step-ca token for {common_name}: {e}"
            ) from e

    def sign_csr(self, csr_pem: bytes, ott_token: str) -> tuple[bytes, list[bytes]]:
        """Submits CSR and one-time token to step-ca POST /1.0/sign."""
        endpoint = f"{self.ca_url}/1.0/sign"
        payload = {
            "csr": csr_pem.decode("utf-8") if isinstance(csr_pem, bytes) else csr_pem,
            "ott": ott_token,
        }

        resp = self.session.post(
            endpoint,
            json=payload,
            verify=self.verify_ssl,
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()

        leaf_pem = data.get("serverPem", "").encode("utf-8")
        chain_list = []
        if "certChainPem" in data and isinstance(data["certChainPem"], list):
            chain_list = [c.encode("utf-8") for c in data["certChainPem"]]
        elif "caPem" in data and data["caPem"]:
            chain_list = [data["caPem"].encode("utf-8")]

        return leaf_pem, chain_list

    def build_p12_bundle(
        self,
        private_key: rsa.RSAPrivateKey,
        cert_pem: bytes,
        intermediate_pem: bytes,
        root_pem: bytes,
        pin: str,
        friendly_name: str = "Wi-Fi Certificate",
    ) -> bytes:
        """Packages private key, leaf cert, and CA chain into an encrypted PKCS#12 bundle."""
        leaf_cert = x509.load_pem_x509_certificate(cert_pem)
        inter_cert = x509.load_pem_x509_certificate(intermediate_pem)
        root_cert = x509.load_pem_x509_certificate(root_pem)

        p12_bytes = pkcs12.serialize_key_and_certificates(
            name=friendly_name.encode("utf-8"),
            key=private_key,
            cert=leaf_cert,
            cas=[inter_cert, root_cert],
            encryption_algorithm=serialization.BestAvailableEncryption(pin.encode("utf-8")),
        )
        return p12_bytes
