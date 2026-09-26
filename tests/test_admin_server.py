from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient

from services.wifi_enrollment.auth import create_session_token
from services.wifi_enrollment.database import CertificateDatabase
from services.wifi_enrollment.models import DevicePlatform, VlanOption
from services.wifi_enrollment.server import create_app
from services.wifi_enrollment.state_manager import StateManager


@pytest.fixture
def admin_test_app(tmp_path):
    db_file = tmp_path / "test_inventory.db"
    db = CertificateDatabase(str(db_file))
    sm = StateManager(ttl_seconds=300)

    step_client = MagicMock()
    step_client.revoke_certificate.return_value = True
    step_client.get_crl.return_value = b"DUMMY_CRL_BYTES"

    radius_client = MagicMock()
    radius_client.delete_user.return_value = True

    slack_handler = MagicMock()
    slack_handler.process_approval.return_value = ("token123", "4829")

    secret = "test-secret"
    allowed_emails = "admin@spoutin.org"

    app = create_app(
        state_manager=sm,
        slack_handler=slack_handler,
        step_client=step_client,
        radius_client=radius_client,
        database=db,
    )
    # Configure test auth
    app.state.session_secret_key = secret
    app.state.allowed_admin_emails = allowed_emails

    client = TestClient(app)
    admin_token = create_session_token("admin@spoutin.org", "Adam", secret_key=secret)
    client.cookies.set("wifi_admin_session", admin_token)

    return client, sm, db, step_client, radius_client, slack_handler


def test_admin_api_unauthorized():
    app = create_app()
    unauth_client = TestClient(app)

    resp = unauth_client.get("/api/admin/stats")
    assert resp.status_code == 401


def test_admin_stats_and_requests(admin_test_app):
    client, sm, db, _, _, _ = admin_test_app

    # Create pending request
    rec = sm.create_request("dev-test", DevicePlatform.ANDROID, "10.0.0.1")

    reqs_resp = client.get("/api/admin/requests")
    assert reqs_resp.status_code == 200
    assert reqs_resp.headers.get("Cache-Control") == "no-store, no-cache, must-revalidate, max-age=0"
    assert reqs_resp.headers.get("Pragma") == "no-cache"
    reqs = reqs_resp.json()
    assert len(reqs) == 1
    assert reqs[0]["device_name"] == "dev-test"
    assert reqs[0]["is_update"] is False

    stats_resp = client.get("/api/admin/stats")
    assert stats_resp.status_code == 200
    assert stats_resp.headers.get("Cache-Control") == "no-store, no-cache, must-revalidate, max-age=0"
    assert stats_resp.json()["total"] == 0

    # Insert existing active certificate for dev-test
    db.insert_certificate(
        serial_number="123456",
        device_name="dev-test",
        platform="android",
        vlan_id=8,
        vlan_label="8 - SemiPrivate",
        client_ip="10.0.0.1",
        cert_pem="PEM",
        issued_at=1000,
        expires_at=2000,
    )
    reqs_resp2 = client.get("/api/admin/requests")
    assert reqs_resp2.json()[0]["is_update"] is True

    stats_resp2 = client.get("/api/admin/stats")
    assert stats_resp2.json()["total"] == 1

    certs_resp = client.get("/api/admin/certificates")
    assert certs_resp.status_code == 200
    assert certs_resp.headers.get("Cache-Control") == "no-store, no-cache, must-revalidate, max-age=0"


def test_admin_web_approval(admin_test_app):
    client, sm, db, _, _, slack_handler = admin_test_app
    rec = sm.create_request("dev-test", DevicePlatform.ANDROID, "10.0.0.1")

    approve_resp = client.post(
        f"/api/admin/requests/{rec.request_id}/approve",
        json={"approved_name": "dev-test-approved", "vlan_id": 8},
    )
    assert approve_resp.status_code == 200
    assert approve_resp.json()["status"] == "approved"

    # Verify slack_handler.process_approval was called
    slack_handler.process_approval.assert_called_once_with(
        request_id=rec.request_id,
        approved_name="dev-test-approved",
        vlan=VlanOption.SEMI_PRIVATE,
    )


def test_admin_web_rejection(admin_test_app):
    client, sm, _, _, _, _ = admin_test_app
    rec = sm.create_request("dev-test", DevicePlatform.ANDROID, "10.0.0.1")

    reject_resp = client.post(
        f"/api/admin/requests/{rec.request_id}/reject",
        json={"reason": "Denied by admin from dashboard"},
    )
    assert reject_resp.status_code == 200
    assert reject_resp.json()["status"] == "rejected"

    updated = sm.get_request(rec.request_id)
    assert updated.status.value == "rejected"


def test_admin_revocation_cert_only(admin_test_app):
    client, sm, db, step_client, radius_client, _ = admin_test_app

    # Seed certificate in database
    db.insert_certificate(
        serial_number="55555",
        device_name="device-to-revoke",
        platform="android",
        vlan_id=8,
        vlan_label="8 - SemiPrivate",
        client_ip="10.0.0.5",
        cert_pem="DUMMY_PEM",
        issued_at=1000,
        expires_at=2000,
    )

    resp = client.post(
        "/api/admin/certificates/55555/revoke",
        json={"reason": "keyCompromise", "scope": "CERT_ONLY"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "revoked"

    # step-ca was called
    step_client.revoke_certificate.assert_called_once_with("55555", reason="keyCompromise")
    # FreeRADIUS delete_user was NOT called
    radius_client.delete_user.assert_not_called()

    cert = db.get_certificate("55555")
    assert cert["status"] == "REVOKED"
    assert cert["revocation_scope"] == "CERT_ONLY"


def test_admin_revocation_user_and_cert(admin_test_app):
    client, sm, db, step_client, radius_client, _ = admin_test_app

    db.insert_certificate(
        serial_number="77777",
        device_name="device-full-revoke",
        platform="ios",
        vlan_id=1,
        vlan_label="1 - LAN",
        client_ip="10.0.0.7",
        cert_pem="DUMMY_PEM",
        issued_at=1000,
        expires_at=2000,
    )

    resp = client.post(
        "/api/admin/certificates/77777/revoke",
        json={"reason": "cessationOfOperation", "scope": "USER_AND_CERT"},
    )
    assert resp.status_code == 200

    step_client.revoke_certificate.assert_called_once_with("77777", reason="cessationOfOperation")
    radius_client.delete_user.assert_called_once_with("device-full-revoke")

    cert = db.get_certificate("77777")
    assert cert["status"] == "REVOKED"
    assert cert["revocation_scope"] == "USER_AND_CERT"


def test_public_crl_route(admin_test_app):
    import hashlib

    client, _, _, step_client, _, _ = admin_test_app
    step_client.get_crl.return_value = b"DUMMY_CRL_BYTES"

    # Initial GET /crl
    resp = client.get("/crl")
    assert resp.status_code == 200
    assert resp.content == b"DUMMY_CRL_BYTES"
    assert "etag" in resp.headers
    etag = resp.headers["etag"]
    expected_etag = f'"{hashlib.sha256(b"DUMMY_CRL_BYTES").hexdigest()}"'
    assert etag == expected_etag
    assert resp.headers["content-type"] == "application/x-pkcs7-crl"
    step_client.get_crl.assert_called_with(as_pem=False)

    # Initial GET /crl.pem
    resp_pem = client.get("/crl.pem")
    assert resp_pem.status_code == 200
    assert resp_pem.headers["content-type"] == "application/x-pem-file"
    step_client.get_crl.assert_called_with(as_pem=True)

    # Conditional GET with matching If-None-Match -> 304 Not Modified
    resp_304 = client.get("/crl.pem", headers={"If-None-Match": etag})
    assert resp_304.status_code == 304
    assert resp_304.content == b""
    assert resp_304.headers["etag"] == etag

    # Conditional GET with outdated If-None-Match -> 200 OK
    resp_updated = client.get("/crl.pem", headers={"If-None-Match": '"outdated-hash"'})
    assert resp_updated.status_code == 200
    assert resp_updated.content == b"DUMMY_CRL_BYTES"


def test_admin_html_pages(admin_test_app):
    client, _, _, _, _, _ = admin_test_app

    # Authenticated client accessing /admin
    admin_page_resp = client.get("/admin")
    assert admin_page_resp.status_code == 200
    assert "Spoutin PKI" in admin_page_resp.text
    assert "Certificate Inventory" in admin_page_resp.text

    # Login page is public
    login_page_resp = client.get("/admin/login")
    assert login_page_resp.status_code == 200
    assert "Sign in with Slack" in login_page_resp.text

    # Unauthenticated access redirects to /admin/login
    client.cookies.clear()
    unauth_resp = client.get("/admin", follow_redirects=False)
    assert unauth_resp.status_code == 302
    assert "/admin/login" in unauth_resp.headers["location"]


def test_admin_events_stream_unauth(admin_test_app):
    client, _, _, _, _, _ = admin_test_app
    client.cookies.clear()
    resp = client.get("/api/admin/events")
    assert resp.status_code == 401


def test_admin_update_vlan(admin_test_app):
    client, _, db, _, radius_client, _ = admin_test_app
    db.insert_certificate(
        serial_number="99999",
        device_name="device-vlan-change",
        platform="android",
        vlan_id=8,
        vlan_label="8 - SemiPrivate",
        client_ip="10.0.0.9",
        cert_pem="PEM",
        issued_at=1000,
        expires_at=2000,
        request_id="req-vlan-test",
    )
    radius_client.update_user_vlan.return_value = True

    resp = client.post(
        "/api/admin/certificates/99999/vlan",
        json={"vlan_id": 1},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["vlan_id"] == 1
    assert "LAN" in data["vlan_label"]

    radius_client.update_user_vlan.assert_called_once_with(
        "device-vlan-change", 1, description="Spoutin PKI | req:req-vlan-test | vlan:1"
    )
    cert = db.get_certificate("99999")
    assert cert["vlan_id"] == 1


def test_admin_sync_radius(admin_test_app):
    client, _, db, _, radius_client, _ = admin_test_app
    db.insert_certificate(
        serial_number="88888",
        device_name="device-sync",
        platform="android",
        vlan_id=8,
        vlan_label="8 - SemiPrivate",
        client_ip="10.0.0.8",
        cert_pem="PEM",
        issued_at=1000,
        expires_at=2000,
    )
    # Mock radius_client.list_users returning changed VLAN 9
    radius_client.list_users.return_value = {
        "device-sync": {"vlan": 9, "uuid": "u8"}
    }

    resp = client.post("/api/admin/sync-radius")
    assert resp.status_code == 200
    assert resp.json()["updated"] == 1

    cert = db.get_certificate("88888")
    assert cert["vlan_id"] == 9
