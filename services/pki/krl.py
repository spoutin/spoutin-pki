"""OpenSSH Key Revocation List (KRL) generator and formatter.

Provides functions to compile binary OpenSSH KRLs using ssh-keygen -k,
self-verify the generated KRL structure with ssh-keygen -Q, and format
plain-text revoked-keys files for OpenSSH's RevokedKeys directive.
"""

import hashlib
import logging
import os
import subprocess
import tempfile
import threading
from typing import Any, Optional

logger = logging.getLogger(__name__)

KRL_MAGIC = b"SSHKRL\n"


def normalize_serial(serial: Any) -> Optional[str]:
    """Normalizes a serial number (decimal or hex string/int) into a valid ssh-keygen decimal string."""
    if serial is None:
        return None
    s = str(serial).strip()
    if not s:
        return None
    try:
        if s.startswith(("0x", "0X")):
            val = int(s, 16)
        elif s.isdigit():
            val = int(s, 10)
        else:
            # Hex string without 0x prefix (e.g. OpenBao '5a72a8b08fcbd083')
            val = int(s, 16)

        if val <= 0:
            return None
        return str(val)
    except ValueError:
        logger.warning("Could not parse serial number as integer or hex: %r", serial)
        return None


def generate_krl(ca_public_key: str, revoked_items: list[dict[str, Any]]) -> bytes:
    """Compiles and self-verifies a binary OpenSSH Key Revocation List (KRL).

    Args:
        ca_public_key: The OpenSSH public key string of the signing CA.
        revoked_items: List of revoked certificate dictionaries from the database.

    Returns:
        The raw bytes of the validated OpenSSH KRL binary.

    Raises:
        RuntimeError: If ssh-keygen -k fails or if the generated KRL fails
            self-verification with ssh-keygen -Q.
    """
    if not ca_public_key or not ca_public_key.strip():
        raise ValueError("CA public key must be provided to generate a KRL")

    with tempfile.TemporaryDirectory() as td:
        ca_pub_path = os.path.join(td, "ca.pub")
        with open(ca_pub_path, "w") as f:
            f.write(ca_public_key.strip() + "\n")

        spec_path = os.path.join(td, "krl-spec.txt")
        with open(spec_path, "w") as f:
            for item in revoked_items:
                norm_serial = normalize_serial(item.get("serial_number"))
                if norm_serial:
                    f.write(f"serial: {norm_serial}\n")

        krl_path = os.path.join(td, "revoked.krl")
        cmd = ["ssh-keygen", "-k", "-f", krl_path, "-s", ca_pub_path, spec_path]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if res.returncode != 0:
            raise RuntimeError(f"ssh-keygen -k failed with exit code {res.returncode}: {res.stderr.strip()}")

        if not os.path.exists(krl_path) or os.path.getsize(krl_path) < 16:
            raise RuntimeError("ssh-keygen -k generated empty or undersized KRL file")

        # Strict Self-Verification: verify that ssh-keygen parses the KRL without errors (rc 0 or 1)
        verify_cmd = ["ssh-keygen", "-Q", "-f", krl_path, ca_pub_path]
        verify_res = subprocess.run(verify_cmd, capture_output=True, text=True, check=False)
        if verify_res.returncode not in (0, 1):
            raise RuntimeError(
                f"Generated KRL failed self-verification check (exit code {verify_res.returncode}): {verify_res.stderr.strip()}"
            )

        with open(krl_path, "rb") as f:
            krl_bytes = f.read()

        if not krl_bytes.startswith(KRL_MAGIC):
            raise RuntimeError(f"Generated KRL missing magic header: expected {KRL_MAGIC!r}, got {krl_bytes[:7]!r}")

        return krl_bytes


def format_revoked_keys_text(revoked_items: list[dict[str, Any]]) -> str:
    """Formats a human-readable plain-text revoked keys file for OpenSSH."""
    lines = [
        "# Spoutin PKI OpenSSH Revoked Keys",
        f"# Total Revoked Certificates: {len(revoked_items)}",
        "# This file can be referenced by 'RevokedKeys' in /etc/ssh/sshd_config",
        "#",
    ]

    if not revoked_items:
        lines.append("# No certificates currently revoked.")
        return "\n".join(lines) + "\n"

    for item in revoked_items:
        raw_serial = item.get("serial_number", "unknown")
        norm_serial = normalize_serial(raw_serial)
        serial_str = f"{raw_serial} (decimal: {norm_serial})" if norm_serial and norm_serial != str(raw_serial) else str(raw_serial)
        key_id = item.get("key_id", "unknown")
        principals = item.get("principals", "")
        cert = item.get("certificate", "").strip()
        pubkey = item.get("public_key", "").strip()

        lines.append(f"# Serial: {serial_str} | Key ID: {key_id} | Principals: {principals}")
        if cert:
            lines.append(cert)
        elif pubkey:
            lines.append(pubkey)
        lines.append("")

    return "\n".join(lines) + "\n"


class KrlManager:
    """Thread-safe manager for caching generated KRL binary and ETag."""

    def __init__(self):
        self._lock = threading.Lock()
        self._cached_krl: Optional[bytes] = None
        self._cached_etag: Optional[str] = None
        self._cached_revoked_hash: Optional[str] = None

    def get_krl(self, ca_public_key: str, revoked_items: list[dict[str, Any]]) -> tuple[bytes, str]:
        """Returns cached or freshly generated KRL bytes and ETag."""
        # Calculate fingerprint of inputs to detect changes
        serials = sorted(str(item.get("serial_number", "")) for item in revoked_items)
        state_key = f"{ca_public_key.strip()}:::{','.join(serials)}"
        revoked_hash = hashlib.sha256(state_key.encode("utf-8")).hexdigest()

        with self._lock:
            if self._cached_krl and self._cached_revoked_hash == revoked_hash:
                return self._cached_krl, self._cached_etag

            krl_bytes = generate_krl(ca_public_key, revoked_items)
            etag = f'"{hashlib.sha256(krl_bytes).hexdigest()}"'

            self._cached_krl = krl_bytes
            self._cached_etag = etag
            self._cached_revoked_hash = revoked_hash

            return krl_bytes, etag

    def invalidate(self) -> None:
        """Invalidates the in-memory cache forcing re-generation on next request."""
        with self._lock:
            self._cached_krl = None
            self._cached_etag = None
            self._cached_revoked_hash = None
