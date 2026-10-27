from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from services.pki.auth import create_session_token
from services.pki.config import settings
from services.pki.database import CertificateDatabase
from services.pki.models import DevicePlatform, VlanOption
from services.pki.server import create_app
from services.pki.state_manager import StateManager


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
    step_client.revoke_certificate.assert_called_once_with("55555", reason="keyCompromise", cert_pem="DUMMY_PEM")
    # CRL was pushed and FreeRADIUS was restarted
    radius_client.push_crl.assert_called_once_with(b"DUMMY_CRL_BYTES")
    radius_client.restart_service.assert_called_once()
    # FreeRADIUS delete_user was NOT called
    radius_client.delete_user.assert_not_called()

    cert = db.get_certificate("55555")
    assert cert["status"] == "REVOKED"
    assert cert["revocation_scope"] == "CERT_ONLY"

    list_resp = client.get("/api/admin/certificates?status=revoked")
    assert list_resp.status_code == 200
    revoked_certs = list_resp.json()
    assert len(revoked_certs) == 1
    assert revoked_certs[0]["revocation_reason"] == "keyCompromise"
    assert revoked_certs[0]["revocation_reason_label"] == "Key Compromise"
    assert revoked_certs[0]["serial_hex"] == "D903"


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

    step_client.revoke_certificate.assert_called_once_with("77777", reason="cessationOfOperation", cert_pem="DUMMY_PEM")
    radius_client.delete_user.assert_called_once_with("device-full-revoke")

    cert = db.get_certificate("77777")
    assert cert["status"] == "REVOKED"
    assert cert["revocation_scope"] == "USER_AND_CERT"


def test_admin_revocation_default_scope(admin_test_app):
    client, sm, db, step_client, radius_client, _ = admin_test_app

    db.insert_certificate(
        serial_number="88888",
        device_name="device-default-revoke",
        platform="android",
        vlan_id=8,
        vlan_label="8 - SemiPrivate",
        client_ip="10.0.0.8",
        cert_pem="DUMMY_PEM",
        issued_at=1000,
        expires_at=2000,
    )

    # Calling revoke with empty body or only reason defaults to USER_AND_CERT
    resp = client.post(
        "/api/admin/certificates/88888/revoke",
        json={},
    )
    assert resp.status_code == 200

    step_client.revoke_certificate.assert_called_once_with("88888", reason="cessationOfOperation", cert_pem="DUMMY_PEM")
    radius_client.delete_user.assert_called_once_with("device-default-revoke")

    cert = db.get_certificate("88888")
    assert cert["status"] == "REVOKED"
    assert cert["revocation_scope"] == "USER_AND_CERT"


def test_admin_revocation_with_infisical_cert_id(admin_test_app):
    client, _, db, ca_client, radius_client, _ = admin_test_app

    db.insert_certificate(
        serial_number="66666",
        device_name="device-infisical",
        platform="android",
        vlan_id=8,
        vlan_label="8 - SemiPrivate",
        client_ip="10.0.0.5",
        cert_pem="DUMMY_PEM",
        issued_at=1000,
        expires_at=2000,
        certificate_id="inf-uuid-12345",
    )

    resp = client.post(
        "/api/admin/certificates/66666/revoke",
        json={"reason": "keyCompromise", "scope": "CERT_ONLY"},
    )
    assert resp.status_code == 200
    ca_client.revoke_certificate.assert_called_with("inf-uuid-12345", reason="keyCompromise", cert_pem="DUMMY_PEM")


def test_admin_download_certificate(admin_test_app):
    client, sm, db, step_client, radius_client, _ = admin_test_app

    # Insert active cert in DB
    db.insert_certificate(
        serial_number="99901",
        device_name="device-dl-test",
        platform="android",
        vlan_id=8,
        vlan_label="8 - SemiPrivate",
        client_ip="10.0.0.9",
        cert_pem="DUMMY_PEM",
        issued_at=1000,
        expires_at=2000,
    )

    # State manager creates and approves request with serial_number
    rec = sm.create_request("device-dl-test", DevicePlatform.ANDROID, "10.0.0.9")
    token, pin = sm.approve_request(
        request_id=rec.request_id,
        approved_name="device-dl-test",
        vlan=VlanOption.SEMI_PRIVATE,
        p12_bytes=b"DUMMY_P12_ADMIN_DOWNLOAD",
        serial_number="99901",
    )

    # Check list certificates includes download_available: True
    list_resp = client.get("/api/admin/certificates")
    assert list_resp.status_code == 200
    matching = [c for c in list_resp.json() if c["serial_number"] == "99901"]
    assert len(matching) == 1
    assert matching[0]["download_available"] is True

    # Admin downloads the certificate
    dl_resp = client.get("/api/admin/certificates/99901/download")
    assert dl_resp.status_code == 200
    assert dl_resp.content == b"DUMMY_P12_ADMIN_DOWNLOAD"
    assert dl_resp.headers["content-type"] == "application/x-pkcs12"
    assert 'attachment; filename="device-dl-test.p12"' in dl_resp.headers["content-disposition"]

    # Repeated download within 24h succeeds
    dl_resp2 = client.get("/api/admin/certificates/99901/download")
    assert dl_resp2.status_code == 200
    assert dl_resp2.content == b"DUMMY_P12_ADMIN_DOWNLOAD"

    # Revoking the certificate purges download
    rev_resp = client.post(
        "/api/admin/certificates/99901/revoke",
        json={"reason": "keyCompromise", "scope": "CERT_ONLY"},
    )
    assert rev_resp.status_code == 200

    # download is now gone / disallowed
    dl_resp_after_rev = client.get("/api/admin/certificates/99901/download")
    assert dl_resp_after_rev.status_code == 400

    # and list_certificates shows download_available: False
    list_resp2 = client.get("/api/admin/certificates")
    matching2 = [c for c in list_resp2.json() if c["serial_number"] == "99901"]
    assert matching2[0]["download_available"] is False


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
        "device-vlan-change", 1, description="Spoutin PKI | vlan:1 | req:req-vlan-test"
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


def test_internal_guest_authorized_endpoint(admin_test_app):
    client, _, db, _, _, _ = admin_test_app

    # Missing X-Internal-Secret returns 401
    resp_no_secret = client.post(
        "/api/internal/guest-authorized",
        json={
            "mac": "00:11:22:33:44:55",
            "name": "Guest Alice",
            "reason": "Meeting",
            "duration_minutes": 1440,
            "approved_by": "admin",
            "approved_at": 1000,
            "expires_at": 1000 + 86400,
        },
    )
    assert resp_no_secret.status_code == 401

    # Pre-record a pending session to verify upsert behavior
    pending_id = db.record_pending_guest(
        mac="00:11:22:33:44:55",
        name="Guest Alice",
        reason="Meeting",
        duration_minutes=1440,
        requested_at=900,
    )

    # With valid secret
    with patch("services.pki.server.resolve_internal_secret", return_value="valid-token-123"):
        with patch.object(client.app.state.broadcaster, "publish_admin") as mock_publish:
            resp = client.post(
                "/api/internal/guest-authorized",
                headers={"X-Internal-Secret": "valid-token-123"},
                json={
                    "mac": "00:11:22:33:44:55",
                    "name": "Guest Alice",
                    "reason": "Meeting",
                    "duration_minutes": 1440,
                    "approved_by": "admin",
                    "approved_at": 1000,
                    "expires_at": 1000 + 86400,
                },
            )
            assert resp.status_code == 200
            assert resp.json()["status"] == "ok"
            assert resp.json()["id"] == pending_id

            mock_publish.assert_called_once_with(
                event="guest_authorized",
                data={
                    "id": pending_id,
                    "mac": "00:11:22:33:44:55",
                    "name": "Guest Alice",
                    "reason": "Meeting",
                    "approved_by": "admin",
                    "duration_minutes": 1440,
                    "approved_at": 1000,
                    "expires_at": 1000 + 86400,
                },
            )

    sessions = db.list_guest_sessions()
    assert len(sessions) == 1
    assert sessions[0]["id"] == pending_id
    assert sessions[0]["mac"] == "00:11:22:33:44:55"
    assert sessions[0]["name"] == "Guest Alice"
    assert sessions[0]["status"] == "ACTIVE"


def test_internal_guest_status_denied(admin_test_app):
    client, _, db, _, _, _ = admin_test_app

    # Pre-record a pending session
    pending_id = db.record_pending_guest(
        mac="aa:bb:cc:dd:ee:99",
        name="Guest Denied",
        reason="Interview",
        duration_minutes=1440,
        requested_at=950,
    )

    # Missing X-Internal-Secret returns 401
    resp_no_secret = client.post(
        "/api/internal/guest/aa:bb:cc:dd:ee:99/status",
        json={"status": "denied", "processedBy": "slack_admin"},
    )
    assert resp_no_secret.status_code == 401

    # With valid secret
    with patch("services.pki.server.resolve_internal_secret", return_value="valid-token-123"):
        with patch.object(client.app.state.broadcaster, "publish_admin") as mock_publish:
            resp = client.post(
                "/api/internal/guest/aa:bb:cc:dd:ee:99/status",
                headers={"X-Internal-Secret": "valid-token-123"},
                json={"status": "denied", "processedBy": "slack_admin"},
            )
            assert resp.status_code == 200
            assert resp.json()["status"] == "denied"
            assert resp.json()["mac"] == "aa:bb:cc:dd:ee:99"

            mock_publish.assert_called_once_with(
                event="guest_denied",
                data={"mac": "aa:bb:cc:dd:ee:99", "denied_by": "slack_admin"},
            )

    sessions = db.list_guest_sessions()
    session = next(s for s in sessions if s["id"] == pending_id)
    assert session["status"] == "DENIED"
    assert session["revoked_by"] == "slack_admin"


def test_admin_list_and_revoke_guests(admin_test_app):
    client, _, db, _, _, _ = admin_test_app
    db.record_guest_session(
        mac="00:11:22:33:44:55",
        name="Guest Bob",
        reason="Vendor",
        duration_minutes=1440,
        approved_by="slack_admin",
        approved_at=1000,
        expires_at=2000,
    )

    mock_unifi = MagicMock()
    mock_unifi.get_active_clients.return_value = {
        "00:11:22:33:44:55": {
            "ip": "10.0.1.50",
            "hostname": "Bob-Laptop",
            "ap_mac": "aa:bb:cc:dd:ee:ff",
            "is_guest": True,
            "usergroup_id": "ug_vip",
        }
    }
    mock_unifi.get_guest_authorizations.return_value = {}
    mock_unifi.revoke_guest.return_value = True

    with patch("services.pki.server.get_unifi_client", return_value=mock_unifi):
        # 1. List guests
        list_resp = client.get("/api/admin/guests")
        assert list_resp.status_code == 200
        guests = list_resp.json()
        assert len(guests) == 1
        assert guests[0]["mac"] == "00:11:22:33:44:55"
        assert guests[0]["online"] is True
        assert guests[0]["ip"] == "10.0.1.50"
        assert guests[0]["usergroup_id"] == "ug_vip"

        # 2. Revoke guest
        revoke_resp = client.post("/api/admin/guests/00:11:22:33:44:55/revoke")
        assert revoke_resp.status_code == 200
        assert revoke_resp.json()["status"] == "revoked"
        mock_unifi.revoke_guest.assert_called_once_with("00:11:22:33:44:55")

    # DB session should now be REVOKED
    sessions = db.list_guest_sessions()
    assert sessions[0]["status"] == "REVOKED"


def test_admin_token_management_endpoints(admin_test_app):
    client, _, db, _, _, _ = admin_test_app

    # 1. Create API token
    create_resp = client.post(
        "/api/admin/tokens",
        json={"name": "unifi-guest-portal-service"},
    )
    assert create_resp.status_code == 200
    data = create_resp.json()
    assert "token" in data
    assert data["token"].startswith("spk_")
    assert data["name"] == "unifi-guest-portal-service"
    token_str = data["token"]
    token_id = data["id"]

    # 2. List tokens
    list_resp = client.get("/api/admin/tokens")
    assert list_resp.status_code == 200
    tokens = list_resp.json()
    assert len(tokens) == 1
    assert tokens[0]["name"] == "unifi-guest-portal-service"
    assert "token" not in tokens[0]  # Full token not exposed

    # 3. Use generated token to authenticate to internal endpoint
    auth_resp = client.post(
        "/api/internal/guest-authorized",
        headers={"X-Internal-Secret": token_str},
        json={
            "mac": "11:22:33:44:55:66",
            "name": "Token Guest",
            "reason": "Test",
            "duration_minutes": 1440,
            "approved_by": "admin",
            "approved_at": 1000,
            "expires_at": 2000,
        },
    )
    assert auth_resp.status_code == 200
    assert auth_resp.json()["status"] == "ok"

    # 4. Revoke token
    del_resp = client.delete(f"/api/admin/tokens/{token_id}")
    assert del_resp.status_code == 200

    # 5. Revoked token fails authentication
    fail_resp = client.post(
        "/api/internal/guest-authorized",
        headers={"X-Internal-Secret": token_str},
        json={
            "mac": "11:22:33:44:55:66",
            "name": "Token Guest",
            "reason": "Test",
            "duration_minutes": 1440,
            "approved_by": "admin",
            "approved_at": 1000,
            "expires_at": 2000,
        },
    )
    assert fail_resp.status_code == 401


def test_admin_sync_unifi_guests_endpoint(admin_test_app):
    client, _, db, _, _, _ = admin_test_app

    mock_unifi = MagicMock()
    mock_unifi.get_all_guests.return_value = [
        {
            "mac": "aa:bb:cc:11:22:33",
            "hostname": "michael-phone",
            "start": 1000,
            "end": 2000,
        }
    ]

    with patch("services.pki.server.get_unifi_client", return_value=mock_unifi):
        resp = client.post("/api/admin/guests/sync")
        assert resp.status_code == 200
        assert resp.json()["status"] == "synced"
        assert resp.json()["inserted"] == 1

    sessions = db.list_guest_sessions()
    assert len(sessions) == 1
    assert sessions[0]["mac"] == "aa:bb:cc:11:22:33"
    assert sessions[0]["name"] == "michael-phone"


def test_admin_get_speed_profiles(admin_test_app):
    client, _, _, _, _, _ = admin_test_app

    mock_unifi = MagicMock()
    mock_unifi.get_user_groups.return_value = [
        {"id": "ug1", "name": "Default", "down_kbps": -1, "up_kbps": -1},
        {"id": "ug2", "name": "50Mbps", "down_kbps": 50000, "up_kbps": 10000},
    ]

    with patch("services.pki.server.get_unifi_client", return_value=mock_unifi):
        resp = client.get("/api/admin/guests/speed-profiles")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        assert data[0]["id"] == "ug1"
        assert data[1]["name"] == "50Mbps"
        mock_unifi.get_user_groups.assert_called_once()


def test_admin_set_guest_speed_profile(admin_test_app):
    client, _, _, _, _, _ = admin_test_app

    mock_unifi = MagicMock()
    mock_unifi.get_user_groups.return_value = [
        {"id": "ug1", "name": "Default", "down_kbps": -1, "up_kbps": -1},
        {"id": "ug2", "name": "50Mbps", "down_kbps": 50000, "up_kbps": 10000},
    ]
    mock_unifi.set_client_user_group.return_value = True

    with patch("services.pki.server.get_unifi_client", return_value=mock_unifi):
        # 1. Invalid profile ID returns 400
        bad_resp = client.post(
            "/api/admin/guests/aa:bb:cc:dd:ee:ff/speed-profile",
            json={"usergroup_id": "nonexistent_group"},
        )
        assert bad_resp.status_code == 400

        # 2. Valid profile ID updates client
        ok_resp = client.post(
            "/api/admin/guests/aa:bb:cc:dd:ee:ff/speed-profile",
            json={"usergroup_id": "ug2"},
        )
        assert ok_resp.status_code == 200
        assert ok_resp.json() == {
            "status": "updated",
            "mac": "aa:bb:cc:dd:ee:ff",
            "usergroup_id": "ug2",
        }
        mock_unifi.set_client_user_group.assert_called_once_with("aa:bb:cc:dd:ee:ff", "ug2")


def test_admin_approve_guest_with_speed_profile(admin_test_app):
    client, _, db, _, _, _ = admin_test_app

    # Create a pending guest session
    db.record_pending_guest(
        mac="00:11:22:33:44:55",
        name="Pending Guest",
        reason="Testing",
        duration_minutes=120,
        requested_at=1000,
    )

    mock_unifi = MagicMock()
    mock_unifi.get_user_groups.return_value = [
        {"id": "ug1", "name": "Default", "down_kbps": -1, "up_kbps": -1},
        {"id": "ug2", "name": "50Mbps", "down_kbps": 50000, "up_kbps": 10000},
    ]
    mock_unifi.authorize_guest.return_value = True
    mock_unifi.set_client_user_group.return_value = True

    with patch("services.pki.server.get_unifi_client", return_value=mock_unifi), \
         patch("services.pki.server.requests.post") as mock_post, \
         patch("services.pki.server.resolve_internal_secret", return_value="portal-secret-abc"):
        resp = client.post(
            "/api/admin/guests/00:11:22:33:44:55/approve",
            json={"duration_minutes": 240, "usergroup_id": "ug2"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "approved"

        # Verify rate limits and set_client_user_group called
        mock_unifi.authorize_guest.assert_called_once_with(
            "00:11:22:33:44:55",
            240,
            up_kbps=10000,
            down_kbps=50000,
        )
        mock_unifi.set_client_user_group.assert_called_once_with("00:11:22:33:44:55", "ug2")

        # Verify captive portal webhook notification uses settings.GUEST_PORTAL_INTERNAL_URL
        expected_portal_url = settings.GUEST_PORTAL_INTERNAL_URL.rstrip("/")
        mock_post.assert_called_once_with(
            f"{expected_portal_url}/api/internal/guest/00:11:22:33:44:55/status",
            json={"status": "approved", "processedBy": "admin@spoutin.org", "durationMinutes": 240},
            headers={
                "Content-Type": "application/json",
                "X-Internal-Secret": "portal-secret-abc",
                "Authorization": "Bearer portal-secret-abc",
            },
            timeout=4,
            verify=False,
        )


def test_admin_deny_guest(admin_test_app):
    client, _, db, _, _, _ = admin_test_app

    # Create a pending guest session
    db.record_pending_guest(
        mac="00:11:22:33:44:55",
        name="Pending Guest",
        reason="Testing Denial",
        duration_minutes=60,
        requested_at=1000,
    )

    with patch("services.pki.server.requests.post") as mock_post, \
         patch("services.pki.server.resolve_internal_secret", return_value="portal-secret-xyz"):
        resp = client.post("/api/admin/guests/00:11:22:33:44:55/deny")
        assert resp.status_code == 200
        assert resp.json() == {"status": "denied", "mac": "00:11:22:33:44:55"}

        # Verify captive portal webhook notification uses settings.GUEST_PORTAL_INTERNAL_URL
        expected_portal_url = settings.GUEST_PORTAL_INTERNAL_URL.rstrip("/")
        mock_post.assert_called_once_with(
            f"{expected_portal_url}/api/internal/guest/00:11:22:33:44:55/status",
            json={"status": "denied", "processedBy": "admin@spoutin.org"},
            headers={
                "Content-Type": "application/json",
                "X-Internal-Secret": "portal-secret-xyz",
                "Authorization": "Bearer portal-secret-xyz",
            },
            timeout=4,
            verify=False,
        )

    sessions = db.list_guest_sessions()
    session = next(s for s in sessions if s["mac"] == "00:11:22:33:44:55")
    assert session["status"] == "DENIED"
    assert session["revoked_by"] == "admin@spoutin.org"


def test_admin_guest_portal_custom_url(admin_test_app, monkeypatch):
    client, _, db, _, _, _ = admin_test_app
    monkeypatch.setattr(settings, "GUEST_PORTAL_INTERNAL_URL", "https://custom-portal.test:8443/")

    db.record_pending_guest(
        mac="aa:bb:cc:11:22:33",
        name="Custom URL Guest",
        reason="Testing",
        duration_minutes=60,
        requested_at=1000,
    )

    with patch("services.pki.server.requests.post") as mock_post, \
         patch("services.pki.server.resolve_internal_secret", return_value="custom-secret"):
        resp = client.post("/api/admin/guests/aa:bb:cc:11:22:33/deny")
        assert resp.status_code == 200
        mock_post.assert_called_once_with(
            "https://custom-portal.test:8443/api/internal/guest/aa:bb:cc:11:22:33/status",
            json={"status": "denied", "processedBy": "admin@spoutin.org"},
            headers={
                "Content-Type": "application/json",
                "X-Internal-Secret": "custom-secret",
                "Authorization": "Bearer custom-secret",
            },
            timeout=4,
            verify=False,
        )


def test_admin_guest_portal_notification_failure_logging(admin_test_app, caplog):
    client, _, db, _, _, _ = admin_test_app
    db.record_pending_guest(
        mac="11:22:33:44:55:66",
        name="Fail Guest",
        reason="Testing",
        duration_minutes=60,
        requested_at=1000,
    )

    with patch("services.pki.server.requests.post", side_effect=Exception("Connection refused")):
        with caplog.at_level("WARNING"):
            resp = client.post("/api/admin/guests/11:22:33:44:55:66/deny")
            assert resp.status_code == 200
            assert "Could not notify captive portal of remote denial: Connection refused" in caplog.text






