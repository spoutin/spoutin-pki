import pytest
from unittest.mock import MagicMock
from fastapi.testclient import TestClient
from services.pki.auth import create_session_token
from services.pki.database import CertificateDatabase
from services.pki.server import create_app


@pytest.fixture
def ssh_app(tmp_path):
    db_file = tmp_path / "test_inventory.db"
    db = CertificateDatabase(str(db_file))

    mock_ca = MagicMock()
    mock_ca.get_ssh_ca_public_key.return_value = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICA_mock_ca_key"
    mock_ca.sign_ssh_public_key.return_value = {
        "serial_number": "555123",
        "signed_key": "ssh-ed25519-cert-v01@openssh.com AAAA... mock_cert",
    }

    mock_slack = MagicMock()
    mock_slack.send_ssh_request_notification.return_value = "123.456"

    app = create_app(
        database=db,
        ca_client=mock_ca,
        slack_handler=mock_slack,
    )
    app.state.session_secret_key = "test-secret"
    app.state.allowed_admin_emails = "admin@spoutin.org"
    return app


@pytest.fixture
def client(ssh_app):
    return TestClient(ssh_app)


@pytest.fixture
def admin_cookie():
    token = create_session_token("admin@spoutin.org", "Adam", secret_key="test-secret")
    return {"wifi_admin_session": token}


def test_get_ssh_ca_pub(client):
    resp = client.get("/ssh-ca.pub")
    assert resp.status_code == 200
    assert "ssh-ed25519" in resp.text
    assert resp.headers["content-type"].startswith("text/plain")


def test_get_ssh_config(client):
    resp = client.get("/api/ssh/config")
    assert resp.status_code == 200
    data = resp.json()
    assert "allowed_principals" in data
    assert "ablack" in data["allowed_principals"]


def test_public_ssh_request_and_status(client):
    # 1. Submit request
    resp = client.post("/api/ssh/request", json={
        "name": "Adam",
        "username": "ablack",
        "device_name": "MacBook",
        "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBXtest user@mac",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "request_id" in data
    assert data["status"] == "PENDING"
    req_id = data["request_id"]

    # 2. Check status
    resp_status = client.get(f"/api/ssh/status/{req_id}")
    assert resp_status.status_code == 200
    assert resp_status.json()["status"] == "PENDING"
    assert resp_status.json()["username"] == "ablack"


def test_admin_quick_sign(client, admin_cookie):
    payload = {
        "key_id": "ablack",
        "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC_user_key ablack@mac",
        "principals": ["ablack", "root", "operator"],
        "ttl": "70080h",
    }
    resp = client.post("/api/admin/ssh/quick-sign", json=payload, cookies=admin_cookie)
    assert resp.status_code == 200
    res = resp.json()
    assert res["serial_number"] == "555123"
    assert res["certificate"].startswith("ssh-ed25519-cert-v01")


def test_admin_ssh_requests_and_approval(client, admin_cookie):
    # Create request
    client.post("/api/ssh/request", json={
        "name": "John",
        "username": "john",
        "device_name": "ThinkPad",
        "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBXtest2 john@laptop",
    })

    # List requests
    resp = client.get("/api/admin/ssh/requests", cookies=admin_cookie)
    assert resp.status_code == 200
    requests = resp.json()
    assert len(requests) >= 1
    req_id = requests[0]["request_id"]

    # Approve request
    resp_app = client.post(
        f"/api/admin/ssh/requests/{req_id}/approve",
        json={"principals": ["operator"], "ttl": "70080h"},
        cookies=admin_cookie,
    )
    assert resp_app.status_code == 200
    assert resp_app.json()["certificate"].startswith("ssh-ed25519-cert-v01")

    # Verify cert appears in certificates list
    resp_certs = client.get("/api/admin/ssh/certificates", cookies=admin_cookie)
    assert resp_certs.status_code == 200
    assert len(resp_certs.json()) >= 1

    # Revoke cert
    resp_rev = client.post(f"/api/admin/ssh/certificates/555123/revoke", cookies=admin_cookie)
    assert resp_rev.status_code == 200


def test_admin_ssh_edit_and_approve(client, admin_cookie):
    # Create request with username "guest"
    client.post("/api/ssh/request", json={
        "name": "Custom User",
        "username": "guest",
        "device_name": "Generic PC",
        "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBXtest3 guest@pc",
    })

    requests = client.get("/api/admin/ssh/requests", cookies=admin_cookie).json()
    req = next(r for r in requests if r["username"] == "guest")

    # Admin changes key_id to "operator", principals to ["operator"], ttl to "24h"
    resp_app = client.post(
        f"/api/admin/ssh/requests/{req['request_id']}/approve",
        json={
            "key_id": "operator",
            "device_name": "Workstation Operator",
            "principals": ["operator"],
            "ttl": "24h",
        },
        cookies=admin_cookie,
    )
    assert resp_app.status_code == 200
    data = resp_app.json()
    assert data["key_id"] == "operator"
    assert data["principals"] == ["operator"]
