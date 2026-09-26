import base64
import hashlib
import hmac
import json
import logging
import time
import urllib.parse
from typing import Optional

import requests
from fastapi import HTTPException, Request

from services.wifi_enrollment.config import settings

logger = logging.getLogger(__name__)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    rem = len(s) % 4
    if rem > 0:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s)


def create_session_token(
    email: str,
    name: str,
    picture: str = "",
    secret_key: Optional[str] = None,
    expires_in: int = 86400,
) -> str:
    """Creates a signed HMAC-SHA256 session token."""
    key = (secret_key or settings.SESSION_SECRET_KEY).encode("utf-8")
    now = int(time.time())

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "email": email.lower(),
        "name": name,
        "picture": picture,
        "iat": now,
        "exp": now + expires_in,
    }

    h_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")

    sig = hmac.new(key, signing_input, hashlib.sha256).digest()
    s_b64 = _b64url_encode(sig)

    return f"{h_b64}.{p_b64}.{s_b64}"


def verify_session_token(token: str, secret_key: Optional[str] = None) -> Optional[dict]:
    """Verifies HMAC-SHA256 signature and expiration of a session token."""
    if not token or token.count(".") != 2:
        return None

    key = (secret_key or settings.SESSION_SECRET_KEY).encode("utf-8")
    h_b64, p_b64, s_b64 = token.split(".")

    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    expected_sig = hmac.new(key, signing_input, hashlib.sha256).digest()

    try:
        actual_sig = _b64url_decode(s_b64)
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None

        payload = json.loads(_b64url_decode(p_b64).decode("utf-8"))
        if time.time() > payload.get("exp", 0):
            return None

        return payload
    except Exception:
        return None


def is_authorized_admin(email: str, allowed_list: Optional[str] = None) -> bool:
    """Checks if an email is in the configured admin allowlist."""
    if not email:
        return False
    raw_list = allowed_list if allowed_list is not None else settings.ADMIN_SLACK_EMAILS
    allowed = [e.strip().lower() for e in raw_list.split(",") if e.strip()]
    return email.strip().lower() in allowed


def generate_slack_oauth_url(client_id: str, redirect_uri: str, state: str) -> str:
    """Generates Slack OpenID Connect authorization URL."""
    params = {
        "response_type": "code",
        "scope": "openid email profile",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
    }
    return f"https://slack.com/openid/connect/authorize?{urllib.parse.urlencode(params)}"


def exchange_slack_code(
    client_id: str, client_secret: str, code: str, redirect_uri: str
) -> dict:
    """Exchanges authorization code for Slack user identity (email, name, picture)."""
    token_url = "https://slack.com/api/openid.connect.token"
    resp = requests.post(
        token_url,
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        },
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()

    if not data.get("ok"):
        raise RuntimeError(f"Slack OAuth token exchange failed: {data.get('error')}")

    # Fetch User Info using access token
    access_token = data.get("access_token")
    user_info_url = "https://slack.com/api/openid.connect.userInfo"
    user_resp = requests.get(
        user_info_url,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    user_resp.raise_for_status()
    user_data = user_resp.json()

    if not user_data.get("ok"):
        raise RuntimeError(f"Failed to fetch Slack user info: {user_data.get('error')}")

    return {
        "email": user_data.get("email", "").lower(),
        "name": user_data.get("name", "Admin"),
        "picture": user_data.get("picture", ""),
        "sub": user_data.get("sub", ""),
    }


def get_current_admin(
    request: Request,
    secret_key: Optional[str] = None,
    allowed_emails: Optional[str] = None,
) -> dict:
    """FastAPI dependency to guard admin routes via session cookie."""
    cookie_token = request.cookies.get("wifi_admin_session")
    if not cookie_token:
        # Also check Authorization: Bearer header for API flexibility
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            cookie_token = auth_header.split(" ", 1)[1]

    if not cookie_token:
        raise HTTPException(status_code=401, detail="Authentication required. Please log in.")

    payload = verify_session_token(cookie_token, secret_key=secret_key)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired session. Please log in again.")

    email = payload.get("email", "")
    if not is_authorized_admin(email, allowed_list=allowed_emails):
        raise HTTPException(
            status_code=403,
            detail=f"Access denied: '{email}' is not in the authorized administrators list.",
        )

    return payload
