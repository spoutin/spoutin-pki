import time
import pytest
from fastapi import HTTPException, Request

from services.wifi_enrollment.auth import (
    create_session_token,
    is_authorized_admin,
    verify_session_token,
    get_current_admin,
)


def test_session_token_roundtrip():
    secret = "test-secret-key-12345"
    token = create_session_token(
        email="adam@spoutin.org",
        name="Adam Black",
        picture="https://example.com/avatar.png",
        secret_key=secret,
        expires_in=3600,
    )
    assert token is not None

    payload = verify_session_token(token, secret_key=secret)
    assert payload is not None
    assert payload["email"] == "adam@spoutin.org"
    assert payload["name"] == "Adam Black"
    assert payload["picture"] == "https://example.com/avatar.png"


def test_session_token_expired():
    secret = "test-secret-key-12345"
    token = create_session_token(
        email="adam@spoutin.org",
        name="Adam Black",
        secret_key=secret,
        expires_in=-10,  # Expired
    )
    assert verify_session_token(token, secret_key=secret) is None


def test_session_token_invalid_signature():
    token = create_session_token(
        email="adam@spoutin.org",
        name="Adam Black",
        secret_key="secret-1",
    )
    assert verify_session_token(token, secret_key="wrong-secret") is None


def test_is_authorized_admin():
    allowed_list = "adam@spoutin.org, admin@int.spoutin.org"
    assert is_authorized_admin("adam@spoutin.org", allowed_list=allowed_list) is True
    assert is_authorized_admin("ADAM@SPOUTIN.ORG", allowed_list=allowed_list) is True
    assert is_authorized_admin("intruder@example.com", allowed_list=allowed_list) is False


def test_get_current_admin_dependency():
    secret = "test-secret-key-12345"
    allowed = "adam@spoutin.org"

    token = create_session_token("adam@spoutin.org", "Adam", secret_key=secret)

    # Valid cookie
    req = Request({"type": "http", "headers": [(b"cookie", f"wifi_admin_session={token}".encode())]})
    admin = get_current_admin(req, secret_key=secret, allowed_emails=allowed)
    assert admin["email"] == "adam@spoutin.org"

    # Missing cookie
    req_empty = Request({"type": "http", "headers": []})
    with pytest.raises(HTTPException) as exc1:
        get_current_admin(req_empty, secret_key=secret, allowed_emails=allowed)
    assert exc1.value.status_code == 401

    # Unauthorized email
    unauth_token = create_session_token("stranger@other.com", "Stranger", secret_key=secret)
    req_unauth = Request({"type": "http", "headers": [(b"cookie", f"wifi_admin_session={unauth_token}".encode())]})
    with pytest.raises(HTTPException) as exc2:
        get_current_admin(req_unauth, secret_key=secret, allowed_emails=allowed)
    assert exc2.value.status_code == 403
