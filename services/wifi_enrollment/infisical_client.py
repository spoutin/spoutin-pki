import base64
import json
import logging
import time
from typing import Optional, Union

import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


class InfisicalCaClient:
    """Client for Infisical PKI API using Universal Auth (Machine Identity)."""

    def __init__(
        self,
        base_url: str = "https://secrets.int.spoutin.org",
        client_id: str = "",
        client_secret: str = "",
        project_id: str = "",
        ca_id: str = "",
        domain: str = "int.spoutin.org",
        default_ttl: str = "52560h",
        verify_ssl: Union[bool, str] = True,
    ):
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.project_id = project_id
        self.ca_id = ca_id
        self.domain = domain
        self.default_ttl = default_ttl
        self.verify_ssl = verify_ssl

        self._access_token: Optional[str] = None
        self._token_expires_at: float = 0.0

        self.session = requests.Session()
        self.session.trust_env = False

    def _ensure_authenticated(self) -> str:
        """Authenticates with Infisical Universal Auth and returns a valid bearer token."""
        now = time.time()
        if self._access_token and now < (self._token_expires_at - 60):
            return self._access_token

        if not self.client_id or not self.client_secret:
            raise ValueError("Infisical client_id and client_secret must be configured.")

        login_url = f"{self.base_url}/api/v1/auth/universal-auth/login"
        payload = {
            "clientId": self.client_id,
            "clientSecret": self.client_secret,
        }
        resp = self.session.post(login_url, json=payload, verify=self.verify_ssl, timeout=10)
        if not resp.ok:
            error_detail = resp.text
            try:
                err_json = resp.json()
                error_detail = err_json.get("message") or err_json.get("detail") or json.dumps(err_json)
            except Exception:
                pass
            raise RuntimeError(f"Infisical Universal Auth login failed (HTTP {resp.status_code}): {error_detail}")

        data = resp.json()
        self._access_token = data.get("accessToken")
        expires_in = int(data.get("expiresIn", 7200))
        self._token_expires_at = now + expires_in
        return self._access_token

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

    def sign_csr(
        self,
        csr_pem: Union[str, bytes],
        ttl: Optional[str] = None,
        ca_id: Optional[str] = None,
    ) -> tuple[str, list[str], str, str]:
        """
        Signs a CSR using Infisical CA.
        Returns tuple: (leaf_cert_pem, chain_pem_list, certificate_id, serial_number)
        """
        token = self._ensure_authenticated()
        target_ca = ca_id or self.ca_id
        if not target_ca:
            raise ValueError("Infisical ca_id must be provided to sign certificate.")

        csr_str = csr_pem.decode("utf-8") if isinstance(csr_pem, bytes) else csr_pem
        endpoint = f"{self.base_url}/api/v1/pki/ca/{target_ca}/sign-certificate"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        payload = {
            "csr": csr_str,
            "ttl": ttl or self.default_ttl,
        }

        resp = self.session.post(endpoint, json=payload, headers=headers, verify=self.verify_ssl, timeout=15)
        if not resp.ok:
            error_detail = resp.text
            try:
                err_json = resp.json()
                error_detail = err_json.get("message") or err_json.get("detail") or json.dumps(err_json)
            except Exception:
                pass
            raise RuntimeError(f"Infisical sign-certificate failed (HTTP {resp.status_code}): {error_detail}")

        data = resp.json()
        cert_data = data.get("certificate", data) if isinstance(data.get("certificate"), dict) else data

        leaf_cert = cert_data.get("certificate") or data.get("certificate")
        chain_raw = cert_data.get("certificateChain") or data.get("certificateChain") or cert_data.get("caChain") or data.get("caChain") or ""
        cert_id = cert_data.get("id") or cert_data.get("certificateId") or data.get("id") or ""
        serial_number = cert_data.get("serialNumber") or data.get("serialNumber") or ""

        chain_list: list[str] = []
        if isinstance(chain_raw, list):
            chain_list = [c.strip() for c in chain_raw if c and c.strip()]
        elif isinstance(chain_raw, str) and chain_raw.strip():
            parts = chain_raw.strip().split("-----END CERTIFICATE-----")
            for p in parts:
                p_clean = p.strip()
                if p_clean:
                    chain_list.append(f"{p_clean}\n-----END CERTIFICATE-----")

        if not serial_number and leaf_cert:
            parsed_cert = x509.load_pem_x509_certificate(leaf_cert.encode("utf-8"))
            serial_number = format(parsed_cert.serial_number, "x")

        return leaf_cert, chain_list, cert_id, serial_number

    def build_p12_bundle(
        self,
        private_key: rsa.RSAPrivateKey,
        cert_pem: Union[str, bytes],
        chain_pems: Union[list[Union[str, bytes]], str, bytes],
        pin: str,
        friendly_name: str = "Wi-Fi Certificate",
    ) -> bytes:
        """Packages private key, leaf cert, and CA chain into an encrypted PKCS#12 bundle."""
        if not cert_pem:
            raise ValueError("Cannot build PKCS#12 bundle: leaf certificate PEM is empty.")

        cert_bytes = cert_pem.encode("utf-8") if isinstance(cert_pem, str) else cert_pem
        leaf_cert = x509.load_pem_x509_certificate(cert_bytes)

        cas = []
        if isinstance(chain_pems, list):
            for c in chain_pems:
                c_bytes = c.encode("utf-8") if isinstance(c, str) else c
                if c_bytes and c_bytes.strip():
                    cas.append(x509.load_pem_x509_certificate(c_bytes.strip()))
        elif isinstance(chain_pems, (str, bytes)):
            chain_str = chain_pems.decode("utf-8") if isinstance(chain_pems, bytes) else chain_pems
            parts = chain_str.strip().split("-----END CERTIFICATE-----")
            for p in parts:
                p_clean = p.strip()
                if p_clean:
                    full_pem = f"{p_clean}\n-----END CERTIFICATE-----"
                    cas.append(x509.load_pem_x509_certificate(full_pem.encode("utf-8")))

        p12_bytes = pkcs12.serialize_key_and_certificates(
            name=friendly_name.encode("utf-8"),
            key=private_key,
            cert=leaf_cert,
            cas=cas if cas else None,
            encryption_algorithm=serialization.BestAvailableEncryption(pin.encode("utf-8")),
        )
        return p12_bytes

    def revoke_certificate(
        self,
        serial_or_id: str,
        reason: int = 0,
        ca_id: Optional[str] = None,
        **kwargs,
    ) -> bool:
        """Revokes a certificate in Infisical by certificate ID or serial number."""
        token = self._ensure_authenticated()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        reason_map = {
            0: "UNSPECIFIED",
            1: "KEY_COMPROMISE",
            2: "CA_COMPROMISE",
            3: "AFFILIATION_CHANGED",
            4: "SUPERSEDED",
            5: "CESSATION_OF_OPERATION",
            6: "CERTIFICATE_HOLD",
        }
        revocation_reason = reason_map.get(reason, "UNSPECIFIED")
        payload = {"revocationReason": revocation_reason}

        # 1. Try revoking via /api/v1/pki/certificates/{id}/revoke
        endpoint_id = f"{self.base_url}/api/v1/pki/certificates/{serial_or_id}/revoke"
        resp = self.session.post(endpoint_id, json=payload, headers=headers, verify=self.verify_ssl, timeout=10)
        if resp.status_code in (200, 204):
            return True

        # 2. Try revoking via /api/v1/pki/ca/{caId}/certificates/{serialNumber}/revoke
        target_ca = ca_id or self.ca_id
        if target_ca:
            endpoint_serial = f"{self.base_url}/api/v1/pki/ca/{target_ca}/certificates/{serial_or_id}/revoke"
            resp_serial = self.session.post(endpoint_serial, json=payload, headers=headers, verify=self.verify_ssl, timeout=10)
            if resp_serial.status_code in (200, 204):
                return True

        if not resp.ok:
            error_detail = resp.text
            try:
                err_json = resp.json()
                error_detail = err_json.get("message") or err_json.get("detail") or json.dumps(err_json)
            except Exception:
                pass
            raise RuntimeError(f"Infisical revoke failed (HTTP {resp.status_code}): {error_detail}")

        return True

    def get_crl(self, as_pem: bool = True, ca_id: Optional[str] = None) -> bytes:
        """Fetches the latest Certificate Revocation List (CRL) from Infisical."""
        token = self._ensure_authenticated()
        target_ca = ca_id or self.ca_id
        if not target_ca:
            raise ValueError("Infisical ca_id must be provided to fetch CRL.")

        endpoint = f"{self.base_url}/api/v1/pki/ca/{target_ca}/crl"
        headers = {"Authorization": f"Bearer {token}"}
        resp = self.session.get(endpoint, headers=headers, verify=self.verify_ssl, timeout=10)
        resp.raise_for_status()

        crl_data = resp.content
        if as_pem:
            if b"-----BEGIN X509 CRL-----" in crl_data:
                return crl_data
            try:
                crl_obj = x509.load_der_x509_crl(crl_data)
                return crl_obj.public_bytes(serialization.Encoding.PEM)
            except Exception:
                return crl_data
        return crl_data

    def get_ca_certificates(self, ca_id: Optional[str] = None) -> tuple[str, list[str]]:
        """Fetches the CA certificate and intermediate chain from Infisical."""
        token = self._ensure_authenticated()
        target_ca = ca_id or self.ca_id
        if not target_ca:
            raise ValueError("Infisical ca_id must be provided to fetch CA certificate.")

        endpoint = f"{self.base_url}/api/v1/pki/ca/{target_ca}/ca-certificates"
        headers = {"Authorization": f"Bearer {token}"}
        resp = self.session.get(endpoint, headers=headers, verify=self.verify_ssl, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        ca_cert = data.get("certificate", "")
        ca_chain = data.get("certificateChain", [])
        return ca_cert, ca_chain
