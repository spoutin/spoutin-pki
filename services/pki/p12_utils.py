"""PKCS#12 bundle conversion utilities (Modern AES-256 vs. Legacy 3DES/SHA1)."""

import logging

from cryptography.hazmat.primitives import hashes
import cryptography.hazmat.primitives._serialization as raw_s
from cryptography.hazmat.primitives.serialization import pkcs12

logger = logging.getLogger(__name__)


def convert_p12_to_legacy(
    p12_bytes: bytes,
    pin: str,
    friendly_name: str = "Spoutin Wi-Fi Certificate",
) -> bytes:
    """Converts a modern PBES2 (AES-256-CBC) PKCS#12 bundle into a legacy 3DES/SHA1

    (pbeWithSHA1And3-KeyTripleDES-CBC) bundle for compatibility with older Android
    keystores (e.g. Samsung Galaxy S10 / Android < 11).
    """
    key, cert, cas = pkcs12.load_key_and_certificates(
        p12_bytes, pin.encode("utf-8")
    )

    builder = raw_s.KeySerializationEncryptionBuilder(raw_s.PrivateFormat.PKCS12)
    builder = builder.key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
    builder = builder.hmac_hash(hashes.SHA1())
    builder = builder.kdf_rounds(2048)
    legacy_encryption = builder.build(pin.encode("utf-8"))

    return pkcs12.serialize_key_and_certificates(
        name=friendly_name.encode("utf-8") if isinstance(friendly_name, str) else friendly_name,
        key=key,
        cert=cert,
        cas=cas,
        encryption_algorithm=legacy_encryption,
    )
