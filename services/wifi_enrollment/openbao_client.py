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


def format_serial_for_openbao(serial: str) -> str:
    """Formats a decimal integer string or hex string into OpenBao's colon-separated hex format."""
    s = str(serial).strip()
    if not s:
        return ""
    if ":" in s or "-" in s:
        return s.replace("-", ":").lower()

    try:
        hex_str = format(int(s), "x")
    except ValueError:
        hex_str = s.lower()

    if len(hex_str) % 2 != 0:
        hex_str = "0" + hex_str

    return ":".join(hex_str[i:i + 2] for i in range(0, len(hex_str), 2)).lower()


class OpenBaoCaClient:
    """Client for OpenBao / HashiCorp Vault PKI Secrets Engine with AppRole authentication."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8200",
        role_id: str = "",
        secret_id: str = "",
        token: str = "",
        pki_mount: str = "pki",
        role_name: str = "wifi-client",
        domain: str = "int.spoutin.org",
        default_ttl: str = "52560h",
        verify_ssl: Union[bool, str] = True,
    ):
        self.base_url = base_url.rstrip("/")
        self.role_id = role_id
        self.secret_id = secret_id
        self.token = token
        self.pki_mount = pki_mount.strip("/")
        self.role_name = role_name
        self.domain = domain
        self.default_ttl = default_ttl
        self.verify_ssl = verify_ssl

        self._cached_token: Optional[str] = None
        self._token_expires_at: float = 0.0

        self.session = requests.Session()
        self.session.trust_env = False

    def _ensure_authenticated(self) -> str:
        """Authenticates with OpenBao via AppRole (or uses static token) and returns a valid client token."""
        # 1. Static token takes precedence if AppRole is not configured
        if self.token and not (self.role_id and self.secret_id):
            return self.token

        # 2. Check cached token validity
        now = time.time()
        if self._cached_token and now < (self._token_expires_at - 60):
            return self._cached_token

        # 3. Authenticate via AppRole
        if not self.role_id or not self.secret_id:
            if self.token:
                return self.token
            raise ValueError("OpenBao authentication requires either (role_id + secret_id) or a token.")

        login_url = f"{self.base_url}/v1/auth/approle/login"
        payload = {
            "role_id": self.role_id,
            "secret_id": self.secret_id,
        }
        resp = self.session.post(login_url, json=payload, verify=self.verify_ssl, timeout=10)
        if not resp.ok:
            error_detail = resp.text
            try:
                err_json = resp.json()
                errors = err_json.get("errors") or [err_json.get("message")]
                error_detail = ", ".join(errors) if errors else resp.text
            except Exception:
                pass
            raise RuntimeError(f"OpenBao AppRole login failed (HTTP {resp.status_code}): {error_detail}")

        data = resp.json()
        auth_data = data.get("auth", {})
        client_token = auth_data.get("client_token")
        if not client_token:
            raise RuntimeError(f"OpenBao AppRole response missing client_token: {data}")

        lease_duration = int(auth_data.get("lease_duration", 3600))
        # If lease_duration is 0 (non-expiring token), set large expiration
        self._token_expires_at = now + (lease_duration if lease_duration > 0 else 86400 * 365)
        self._cached_token = client_token
        return self._cached_token

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
        role_name: Optional[str] = None,
    ) -> tuple[str, list[str], Optional[str], str]:
        """
        Signs a CSR using OpenBao PKI role.
        Returns tuple: (leaf_cert_pem, chain_pem_list, None, serial_number)
        """
        token = self._ensure_authenticated()
        role = role_name or self.role_name
        csr_str = csr_pem.decode("utf-8") if isinstance(csr_pem, bytes) else csr_pem

        endpoint = f"{self.base_url}/v1/{self.pki_mount}/sign/{role}"
        headers = {
            "X-Vault-Token": token,
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
                errors = err_json.get("errors") or [err_json.get("message")]
                error_detail = ", ".join(errors) if errors else resp.text
            except Exception:
                pass
            raise RuntimeError(f"OpenBao sign-certificate failed (HTTP {resp.status_code}): {error_detail}")

        data = resp.json().get("data", {})
        leaf_cert = data.get("certificate", "")
        ca_chain = data.get("ca_chain", [])
        raw_serial = data.get("serial_number", "")

        # Fallback if ca_chain not a list
        chain_list: list[str] = []
        if isinstance(ca_chain, list) and ca_chain:
            chain_list = [c.strip() for c in ca_chain if c and c.strip()]
        elif data.get("issuing_ca"):
            chain_list = [data["issuing_ca"].strip()]

        clean_serial = raw_serial.replace(":", "").lower().strip()
        if not clean_serial and leaf_cert:
            parsed_cert = x509.load_pem_x509_certificate(leaf_cert.encode("utf-8"))
            clean_serial = format(parsed_cert.serial_number, "x")

        return leaf_cert, chain_list, None, clean_serial

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
        serial_number: str,
        reason: int = 0,
        cert_pem: Optional[str] = None,
        **kwargs,
    ) -> bool:
        """Revokes a certificate in OpenBao by serial number or certificate PEM."""
        token = self._ensure_authenticated()
        endpoint = f"{self.base_url}/v1/{self.pki_mount}/revoke"
        headers = {
            "X-Vault-Token": token,
            "Content-Type": "application/json",
        }
        if "BEGIN CERTIFICATE" in serial_number:
            payload = {"certificate": serial_number}
        else:
            clean_serial = format_serial_for_openbao(serial_number)
            payload = {"serial_number": clean_serial}

        resp = self.session.post(endpoint, json=payload, headers=headers, verify=self.verify_ssl, timeout=10)
        if resp.status_code in (200, 204):
            return True

        # Fallback 1: if not found in OpenBao storage by serial, try revoking by certificate PEM if available
        if cert_pem and "BEGIN CERTIFICATE" in cert_pem:
            resp_pem = self.session.post(endpoint, json={"certificate": cert_pem}, headers=headers, verify=self.verify_ssl, timeout=10)
            if resp_pem.status_code in (200, 204):
                return True

        # Fallback 2: try plain hex without colons
        if "serial_number" in payload and ":" in payload["serial_number"]:
            plain_serial = payload["serial_number"].replace(":", "")
            resp_plain = self.session.post(endpoint, json={"serial_number": plain_serial}, headers=headers, verify=self.verify_ssl, timeout=10)
            if resp_plain.status_code in (200, 204):
                return True

        if not resp.ok:
            error_detail = resp.text
            try:
                err_json = resp.json()
                errors = err_json.get("errors") or [err_json.get("message")]
                error_detail = ", ".join(errors) if errors else resp.text
            except Exception:
                pass
            raise RuntimeError(f"OpenBao revoke failed (HTTP {resp.status_code}): {error_detail}")

        return True

    def get_crl(self, as_pem: bool = True) -> bytes:
        """Fetches the latest Certificate Revocation List (CRL) from OpenBao."""
        token = self._ensure_authenticated()
        crl_path = "crl/pem" if as_pem else "crl"
        endpoint = f"{self.base_url}/v1/{self.pki_mount}/{crl_path}"
        headers = {"X-Vault-Token": token}

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
