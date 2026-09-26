import base64
import hashlib
import json
import logging
import os
import time
import urllib.parse
import uuid
from typing import Optional, Union

import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.primitives.serialization import pkcs12

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


def base64url_decode(s: str) -> bytes:
    """Decodes base64url string with padding restoration."""
    rem = len(s) % 4
    if rem > 0:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s)


def base64url_encode(data: Union[bytes, str]) -> str:
    """Encodes bytes or str into unpadded base64url."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def decrypt_jwe_key(encrypted_key_jwe: str, password: str) -> ec.EllipticCurvePrivateKey:
    """Decrypts a step-ca JWK provisioner key (PBES2-HS256+A128KW / A256GCM)."""
    parts = encrypted_key_jwe.split(".")
    if len(parts) != 5:
        raise ValueError("Invalid JWE format: expected 5 dot-separated parts")

    header_b64, enc_key_b64, iv_b64, ct_b64, tag_b64 = parts
    header = json.loads(base64url_decode(header_b64))

    alg = header.get("alg")
    enc = header.get("enc")
    if alg != "PBES2-HS256+A128KW" or enc != "A256GCM":
        raise ValueError(f"Unsupported JWE algorithms: alg={alg}, enc={enc}")

    p2s = base64url_decode(header["p2s"])
    p2c = int(header.get("p2c", 100000))

    # Derive KEK via PBKDF2
    salt = b"PBES2-HS256+A128KW\x00" + p2s
    kek = PBKDF2HMAC(
        hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=p2c,
    ).derive(password.encode("utf-8"))

    # Unwrap AES-GCM Content Encryption Key (CEK)
    cek = aes_key_unwrap(kek, base64url_decode(enc_key_b64))

    # Decrypt JWE ciphertext using AES-256-GCM
    iv = base64url_decode(iv_b64)
    ciphertext = base64url_decode(ct_b64)
    tag = base64url_decode(tag_b64)
    aad = header_b64.encode("ascii")

    aesgcm = AESGCM(cek)
    plaintext = aesgcm.decrypt(iv, ciphertext + tag, aad)
    jwk = json.loads(plaintext.decode("utf-8"))

    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError(f"Unsupported JWK key type/curve: {jwk.get('kty')}/{jwk.get('crv')}")

    d_int = int.from_bytes(base64url_decode(jwk["d"]), byteorder="big")
    return ec.derive_private_key(d_int, ec.SECP256R1())


class StepCaClient:
    """Pure REST API client for step-ca with in-memory key generation and JWT token signing."""

    def __init__(
        self,
        ca_url: str = "https://127.0.0.1:9000",
        domain: str = "int.spoutin.org",
        provisioner_name: str = "admin@int.spoutin.org",
        ca_config_path: str = "/etc/step-ca/config/ca.json",
        password_file: str = "/etc/step-ca/password.txt",
        provisioner_key_path: str = "/etc/step-ca/secrets/provisioner_key.json",
        provisioner_password: str = "",
        root_cert_path: str = "/etc/step-ca/certs/root_ca.crt",
        intermediate_cert_path: str = "/etc/step-ca/certs/intermediate_ca.crt",
        verify_ssl: Union[bool, str] = False,
        provisioner_private_key: Optional[ec.EllipticCurvePrivateKey] = None,
        provisioner_kid: Optional[str] = None,
    ):
        self.ca_url = ca_url.rstrip("/")
        self.domain = domain
        self.provisioner_name = provisioner_name
        self.ca_config_path = ca_config_path
        self.password_file = password_file
        self.provisioner_key_path = provisioner_key_path
        self.provisioner_password = provisioner_password
        self.root_cert_path = root_cert_path
        self.intermediate_cert_path = intermediate_cert_path
        self.verify_ssl = verify_ssl

        # In-memory cached key & kid
        self._cached_private_key = provisioner_private_key
        self._cached_kid = provisioner_kid
        self._cached_root_fingerprint = None

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

    def get_root_fingerprint(self) -> str:
        """Retrieves or calculates the SHA-256 fingerprint of the Root CA directly from raw DER bytes."""
        if self._cached_root_fingerprint:
            return self._cached_root_fingerprint

        if os.path.exists(self.root_cert_path):
            with open(self.root_cert_path, "rb") as f:
                lines = [l.strip() for l in f.read().splitlines()]
                b64_lines = [l for l in lines if not l.startswith(b"-----") and len(l) > 0]
                der_bytes = base64.b64decode(b"".join(b64_lines))
                self._cached_root_fingerprint = hashlib.sha256(der_bytes).hexdigest().lower()
                return self._cached_root_fingerprint

        return ""

    def get_provisioner_key(self) -> tuple[ec.EllipticCurvePrivateKey, str]:
        """Loads and decrypts the provisioner private key and key ID in-memory."""
        if self._cached_private_key and self._cached_kid:
            return self._cached_private_key, self._cached_kid

        # 1. Try reading password from password_file or environment
        password = self.provisioner_password
        if not password and os.path.exists(self.password_file):
            with open(self.password_file, "r", encoding="utf-8") as f:
                password = f.read().strip()

        # 2. Try loading from ca.json if available
        if os.path.exists(self.ca_config_path):
            with open(self.ca_config_path, "r", encoding="utf-8") as f:
                ca_json = json.load(f)

            provisioners = ca_json.get("authority", {}).get("provisioners", [])
            target = None
            for p in provisioners:
                if p.get("name") == self.provisioner_name and p.get("type") == "JWK":
                    target = p
                    break
            if not target and provisioners:
                target = provisioners[0]

            if target:
                kid = target.get("key", {}).get("kid", "")
                enc_key = target.get("encryptedKey", "")
                if enc_key and password:
                    logger.info("Decrypting step-ca provisioner key from ca.json in memory...")
                    priv_key = decrypt_jwe_key(enc_key, password)
                    self._cached_private_key = priv_key
                    self._cached_kid = kid
                    return priv_key, kid

        raise RuntimeError(
            f"Could not load provisioner private key for '{self.provisioner_name}'. "
            f"Ensure {self.ca_config_path} and {self.password_file} are accessible."
        )

    def generate_provisioner_token(self, common_name: str) -> str:
        """Generates a signed ES256 JWT one-time token (OTT) completely in Python."""
        private_key, kid = self.get_provisioner_key()

        sans = [common_name]
        if self.domain and not common_name.endswith(f".{self.domain}"):
            sans.append(f"{common_name}.{self.domain}")

        # Construct audiences list: step-ca matches audiences against its dnsNames without port numbers,
        # plus the built-in legacyAuthority ("step-certificate-authority")
        parsed = urllib.parse.urlparse(self.ca_url)
        ca_host = parsed.hostname or "127.0.0.1"

        audiences = [
            "step-certificate-authority",
            f"https://step-ca.{self.domain}/1.0/sign",
            f"https://{self.domain}/1.0/sign",
            "https://step-ca/1.0/sign",
            "https://localhost/1.0/sign",
        ]
        if ca_host not in ("step-ca", "localhost"):
            audiences.append(f"https://{ca_host}/1.0/sign")
        audiences.append(f"{self.ca_url}/1.0/sign")

        # Deduplicate while preserving order
        clean_audiences = []
        seen = set()
        for a in audiences:
            if a not in seen:
                seen.add(a)
                clean_audiences.append(a)

        now = int(time.time())
        header = {
            "alg": "ES256",
            "kid": kid,
            "typ": "JWT",
        }
        payload = {
            "aud": clean_audiences,
            "exp": now + 300,  # 5 minutes
            "iat": now,
            "iss": self.provisioner_name,
            "jti": str(uuid.uuid4()),
            "nbf": now,
            "sans": sans,
            "sha": self.get_root_fingerprint(),
            "sub": common_name,
        }

        header_b64 = base64url_encode(json.dumps(header, separators=(",", ":")))
        payload_b64 = base64url_encode(json.dumps(payload, separators=(",", ":")))
        signing_input = f"{header_b64}.{payload_b64}"

        # Sign with ECDSA P-256 SHA-256
        der_signature = private_key.sign(
            signing_input.encode("ascii"),
            ec.ECDSA(hashes.SHA256()),
        )
        r, s = decode_dss_signature(der_signature)
        raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        sig_b64 = base64url_encode(raw_signature)

        return f"{signing_input}.{sig_b64}"

    def sign_csr(self, csr_pem: bytes, ott_token: str) -> tuple[bytes, list[bytes]]:
        """Submits CSR and one-time token to step-ca POST /1.0/sign via REST API."""
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

        if not resp.ok:
            error_detail = resp.text
            try:
                err_json = resp.json()
                error_detail = err_json.get("message") or err_json.get("detail") or json.dumps(err_json)
            except Exception:
                pass
            msg = f"step-ca sign failed (HTTP {resp.status_code}): {error_detail}"
            logger.error(msg)
            raise RuntimeError(msg)

        data = resp.json()

        # step-ca SignResponse schema: {"crt": "...", "ca": "...", "certChain": ["..."]}
        raw_leaf = data.get("crt") or data.get("serverPem") or data.get("certificate") or ""
        if not raw_leaf:
            raise ValueError(f"step-ca response missing certificate ('crt'): keys in response are {list(data.keys())}")

        leaf_pem = raw_leaf.encode("utf-8") if isinstance(raw_leaf, str) else raw_leaf

        chain_list = []
        raw_chain = data.get("certChain") or data.get("certChainPem")
        if raw_chain and isinstance(raw_chain, list):
            chain_list = [c.encode("utf-8") if isinstance(c, str) else c for c in raw_chain]
        elif data.get("ca"):
            raw_ca = data.get("ca")
            chain_list = [raw_ca.encode("utf-8") if isinstance(raw_ca, str) else raw_ca]
        elif data.get("caPem"):
            raw_ca = data.get("caPem")
            chain_list = [raw_ca.encode("utf-8") if isinstance(raw_ca, str) else raw_ca]

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
        if not cert_pem or not cert_pem.strip():
            raise ValueError("Cannot build PKCS#12 bundle: leaf certificate PEM is empty.")

        leaf_cert = x509.load_pem_x509_certificate(cert_pem)
        inter_cert = x509.load_pem_x509_certificate(intermediate_pem) if intermediate_pem and intermediate_pem.strip() else None
        root_cert = x509.load_pem_x509_certificate(root_pem) if root_pem and root_pem.strip() else None

        cas = [c for c in [inter_cert, root_cert] if c is not None]

        p12_bytes = pkcs12.serialize_key_and_certificates(
            name=friendly_name.encode("utf-8"),
            key=private_key,
            cert=leaf_cert,
            cas=cas,
            encryption_algorithm=serialization.BestAvailableEncryption(pin.encode("utf-8")),
        )
        return p12_bytes
