import hashlib
import secrets


def generate_api_token(prefix: str = "spk") -> tuple[str, str, str]:
    """
    Generates a secure API token.
    Returns:
        (raw_token, token_hash, token_preview)
    """
    random_part = secrets.token_hex(24)
    raw_token = f"{prefix}_{random_part}"
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    token_preview = f"{raw_token[:8]}...{raw_token[-4:]}"
    return raw_token, token_hash, token_preview
