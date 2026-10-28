import time
import pytest
from services.pki.database import CertificateDatabase


@pytest.fixture
def db(tmp_path):
    db_file = tmp_path / "test_inventory.db"
    return CertificateDatabase(str(db_file))


def test_insert_and_get_certificate(db):
    now = int(time.time())
    db.insert_certificate(
        serial_number="277517881126958304008076931320810468676",
        device_name="ablack-phone1",
        platform="android",
        vlan_id=8,
        vlan_label="8 - SemiPrivate",
        client_ip="10.0.0.196",
        cert_pem="-----BEGIN CERTIFICATE-----\nTEST_PEM\n-----END CERTIFICATE-----",
        issued_at=now,
        expires_at=now + 52560 * 3600,
        opnsense_uuid="uuid-abcd-1234",
    )

    cert = db.get_certificate("277517881126958304008076931320810468676")
    assert cert is not None
    assert cert["device_name"] == "ablack-phone1"
    assert cert["platform"] == "android"
    assert cert["vlan_id"] == 8
    assert cert["vlan_label"] == "8 - SemiPrivate"
    assert cert["status"] == "ACTIVE"
    assert cert["opnsense_uuid"] == "uuid-abcd-1234"
    assert cert["revoked_at"] is None


def test_list_and_filter_certificates(db):
    now = int(time.time())
    db.insert_certificate(
        serial_number="1111",
        device_name="phone-alpha",
        platform="ios",
        vlan_id=8,
        vlan_label="8 - SemiPrivate",
        client_ip="10.0.0.10",
        cert_pem="PEM1",
        issued_at=now,
        expires_at=now + 1000,
    )
    db.insert_certificate(
        serial_number="2222",
        device_name="phone-beta",
        platform="android",
        vlan_id=1,
        vlan_label="1 - LAN",
        client_ip="10.0.0.20",
        cert_pem="PEM2",
        issued_at=now,
        expires_at=now + 1000,
    )

    # Search filter
    results = db.list_certificates(search="alpha")
    assert len(results) == 1
    assert results[0]["device_name"] == "phone-alpha"

    # VLAN filter
    vlan1_results = db.list_certificates(vlan_id=1)
    assert len(vlan1_results) == 1
    assert vlan1_results[0]["device_name"] == "phone-beta"

    # Status filter
    active_results = db.list_certificates(status="ACTIVE")
    assert len(active_results) == 2

    # Hex lookup and search
    # Decimal 2222 in hex is 8AE
    assert db.get_certificate("8AE") is not None
    assert db.get_certificate("8AE")["device_name"] == "phone-beta"
    hex_search_results = db.list_certificates(search="8AE")
    assert len(hex_search_results) == 1
    assert hex_search_results[0]["device_name"] == "phone-beta"


def test_revoke_certificate(db):
    now = int(time.time())
    db.insert_certificate(
        serial_number="3333",
        device_name="test-device",
        platform="windows",
        vlan_id=9,
        vlan_label="9 - IoT",
        client_ip="10.0.0.30",
        cert_pem="PEM3",
        issued_at=now,
        expires_at=now + 1000,
    )

    success = db.revoke_certificate(
        serial_number="3333",
        reason="Device decommissioned",
        scope="USER_AND_CERT",
    )
    assert success is True

    cert = db.get_certificate("3333")
    assert cert["status"] == "REVOKED"
    assert cert["revocation_reason"] == "Device decommissioned"
    assert cert["revocation_scope"] == "USER_AND_CERT"
    assert cert["revoked_at"] is not None


def test_get_stats(db):
    now = int(time.time())
    db.insert_certificate(
        serial_number="100",
        device_name="dev1",
        platform="android",
        vlan_id=8,
        vlan_label="8 - SemiPrivate",
        client_ip="10.0.0.1",
        cert_pem="PEM",
        issued_at=now,
        expires_at=now + 1000,
    )
    db.insert_certificate(
        serial_number="200",
        device_name="dev2",
        platform="ios",
        vlan_id=8,
        vlan_label="8 - SemiPrivate",
        client_ip="10.0.0.2",
        cert_pem="PEM",
        issued_at=now,
        expires_at=now + 1000,
    )
    db.revoke_certificate(serial_number="200", reason="Retired", scope="CERT_ONLY")

    stats = db.get_stats()
    assert stats["total"] == 2
    assert stats["active"] == 1
    assert stats["revoked"] == 1
    assert stats["by_vlan"][8] == 1


def test_update_certificate_vlan(db):
    now = int(time.time())
    db.insert_certificate(
        serial_number="5555",
        device_name="device-vlan-test",
        platform="android",
        vlan_id=8,
        vlan_label="8 - SemiPrivate",
        client_ip="10.0.0.1",
        cert_pem="PEM",
        issued_at=now,
        expires_at=now + 1000,
    )

    updated = db.update_certificate_vlan("5555", 1, "1 - LAN")
    assert updated is True

    cert = db.get_certificate("5555")
    assert cert["vlan_id"] == 1
    assert cert["vlan_label"] == "1 - LAN"

    # Update by device name
    changed = db.update_vlan_by_device_name("device-vlan-test", 9, "9 - IoT")
    assert changed == 1
    cert2 = db.get_certificate("5555")
    assert cert2["vlan_id"] == 9
    assert cert2["vlan_label"] == "9 - IoT"


def test_request_id_and_device_name_exists(db):
    now = int(time.time())
    db.insert_certificate(
        serial_number="7777",
        device_name="device-req-test",
        platform="android",
        vlan_id=8,
        vlan_label="8 - SemiPrivate",
        client_ip="10.0.0.1",
        cert_pem="PEM",
        issued_at=now,
        expires_at=now + 1000,
        request_id="req-test-999",
        pin="1234",
    )

    cert = db.get_certificate("7777")
    assert cert["request_id"] == "req-test-999"
    assert cert["pin"] == "1234"

    # Search by request_id
    res = db.list_certificates(search="req-test-999")
    assert len(res) == 1
    assert res[0]["serial_number"] == "7777"

    # Check device_name_exists
    assert db.device_name_exists("device-req-test") is True
    assert db.device_name_exists("nonexistent-device") is False


def test_guest_session_crud(db):
    now = int(time.time())
    db.record_guest_session(
        mac="00:11:22:33:44:55",
        name="Guest Alice",
        reason="Consultant",
        duration_minutes=1440,
        approved_by="slack_admin",
        approved_at=now,
        expires_at=now + 86400,
    )

    sessions = db.list_guest_sessions()
    assert len(sessions) == 1
    assert sessions[0]["mac"] == "00:11:22:33:44:55"
    assert sessions[0]["name"] == "Guest Alice"
    assert sessions[0]["status"] == "ACTIVE"

    # Revoke session
    ok = db.revoke_guest_session(mac="00:11:22:33:44:55", revoked_by="admin@example.com")
    assert ok is True

    updated_sessions = db.list_guest_sessions()
    assert len(updated_sessions) == 1
    assert updated_sessions[0]["status"] == "REVOKED"
    assert updated_sessions[0]["revoked_by"] == "admin@example.com"


def test_extend_guest_session(db):
    now = int(time.time())
    db.record_guest_session(
        mac="00:11:22:33:44:55",
        name="Guest Alice",
        reason="Consultant",
        duration_minutes=1440,
        approved_by="slack_admin",
        approved_at=now,
        expires_at=now + 86400,
    )

    # Extend active session
    new_expires = now + 86400 + 86400
    res = db.extend_guest_session(mac="00:11:22:33:44:55", additional_minutes=1440, new_expires_at=new_expires)
    assert res is True

    sessions = db.list_guest_sessions()
    assert len(sessions) == 1
    assert sessions[0]["expires_at"] == new_expires
    assert sessions[0]["duration_minutes"] == 2880

    # Extend case-insensitive mac with spaces
    new_expires_2 = new_expires + (4320 * 60)
    res = db.extend_guest_session(mac=" 00:11:22:33:44:55 ", additional_minutes=4320, new_expires_at=new_expires_2)
    assert res is True
    sessions = db.list_guest_sessions()
    assert sessions[0]["expires_at"] == new_expires_2
    assert sessions[0]["duration_minutes"] == 2880 + 4320

    # Non-existent or non-active session returns False
    res_non_existent = db.extend_guest_session(mac="ff:ff:ff:ff:ff:ff", additional_minutes=1440, new_expires_at=new_expires)
    assert res_non_existent is False

    # Revoke it, then try extending -> returns False
    db.revoke_guest_session(mac="00:11:22:33:44:55", revoked_by="admin")
    res_revoked = db.extend_guest_session(mac="00:11:22:33:44:55", additional_minutes=1440, new_expires_at=new_expires)
    assert res_revoked is False


def test_set_guest_session_expiry(db):
    now = int(time.time())
    db.record_guest_session(
        mac="00:11:22:33:44:55",
        name="Guest Bob",
        reason="Partner Meeting",
        duration_minutes=1440,
        approved_by="slack_admin",
        approved_at=now,
        expires_at=now + 86400,
    )

    # Set expiry to 2 days from approval
    new_expires = now + 172800
    res = db.set_guest_session_expiry(mac="00:11:22:33:44:55", new_expires_at=new_expires)
    assert res is True

    sessions = db.list_guest_sessions()
    assert len(sessions) == 1
    assert sessions[0]["expires_at"] == new_expires
    assert sessions[0]["duration_minutes"] == 2880

    # Reduce expiry to 1 hour from approval
    reduced_expires = now + 3600
    res = db.set_guest_session_expiry(mac="00:11:22:33:44:55", new_expires_at=reduced_expires)
    assert res is True
    sessions = db.list_guest_sessions()
    assert sessions[0]["expires_at"] == reduced_expires
    assert sessions[0]["duration_minutes"] == 60

    # Normalization check: lowercase and whitespace
    whitespace_expires = now + 7200
    res = db.set_guest_session_expiry(mac="  00:11:22:33:44:55  ", new_expires_at=whitespace_expires)
    assert res is True
    sessions = db.list_guest_sessions()
    assert sessions[0]["expires_at"] == whitespace_expires
    assert sessions[0]["duration_minutes"] == 120

    # Non-existent session
    assert db.set_guest_session_expiry(mac="ff:ff:ff:ff:ff:ff", new_expires_at=now + 3600) is False

    # Revoked session
    db.revoke_guest_session(mac="00:11:22:33:44:55", revoked_by="admin")
    assert db.set_guest_session_expiry(mac="00:11:22:33:44:55", new_expires_at=now + 3600) is False




def test_record_guest_session_upsert_pending(db):
    now = int(time.time())
    # 1. Record a pending guest session
    pending_id = db.record_pending_guest(
        mac="AA:BB:CC:DD:EE:FF",
        name="Pending Bob",
        reason="Interview",
        duration_minutes=1440,
        requested_at=now,
    )
    assert pending_id > 0

    sessions = db.list_guest_sessions()
    assert len(sessions) == 1
    assert sessions[0]["id"] == pending_id
    assert sessions[0]["status"] == "PENDING"
    assert sessions[0]["name"] == "Pending Bob"

    # 2. Authorize via record_guest_session with same MAC (case-insensitive)
    auth_id = db.record_guest_session(
        mac="aa:bb:cc:dd:ee:ff",
        name="Bob Smith",
        reason="Final Interview",
        duration_minutes=2880,
        approved_by="slack_approver",
        approved_at=now + 60,
        expires_at=now + 60 + 2880 * 60,
    )
    # Must return existing row id, NOT create a duplicate
    assert auth_id == pending_id

    sessions_after = db.list_guest_sessions()
    assert len(sessions_after) == 1
    session = sessions_after[0]
    assert session["id"] == pending_id
    assert session["status"] == "ACTIVE"
    assert session["name"] == "Bob Smith"
    assert session["reason"] == "Final Interview"
    assert session["duration_minutes"] == 2880
    assert session["approved_by"] == "slack_approver"
    assert session["approved_at"] == now + 60
    assert session["expires_at"] == now + 60 + 2880 * 60

    # 3. Subsequent record_guest_session with active session returns existing ID and updates details
    active_id = db.record_guest_session(
        mac="AA:BB:CC:DD:EE:FF",
        name="Bob Smith Updated",
        reason="Updated reason",
        duration_minutes=2880,
        approved_by="slack_approver_2",
        approved_at=now + 120,
        expires_at=now + 120 + 2880 * 60,
    )
    assert active_id == pending_id
    sessions_after_update = db.list_guest_sessions()
    assert len(sessions_after_update) == 1
    session_updated = sessions_after_update[0]
    assert session_updated["id"] == pending_id
    assert session_updated["name"] == "Bob Smith Updated"
    assert session_updated["approved_by"] == "slack_approver_2"


def test_approve_guest_session_atomic(db):
    now = int(time.time())
    pending_id = db.record_pending_guest(
        mac="00:11:22:33:44:99",
        name="Atomic Test",
        reason="Testing Atomic Approval",
        duration_minutes=60,
        requested_at=now,
    )
    assert pending_id > 0

    # First approval should succeed
    res1 = db.approve_guest_session(
        mac="00:11:22:33:44:99",
        approved_by="admin",
        duration_minutes=60,
        approved_at=now,
        expires_at=now + 3600,
    )
    assert res1 is True

    # Second approval on already ACTIVE session should return False
    res2 = db.approve_guest_session(
        mac="00:11:22:33:44:99",
        approved_by="admin",
        duration_minutes=60,
        approved_at=now,
        expires_at=now + 3600,
    )
    assert res2 is False


def test_deny_guest_session(db):
    now = int(time.time())
    pending_id = db.record_pending_guest(
        mac="11:22:33:44:55:66",
        name="Charlie",
        reason="Visitor",
        duration_minutes=1440,
        requested_at=now,
    )
    assert pending_id > 0

    ok = db.deny_guest_session("11:22:33:44:55:66", denied_by="admin@spoutin.org")
    assert ok is True

    sessions = db.list_guest_sessions()
    denied_session = next(s for s in sessions if s["id"] == pending_id)
    assert denied_session["status"] == "DENIED"
    assert denied_session["revoked_by"] == "admin@spoutin.org"
    assert denied_session["revoked_at"] is not None

    # Revoking makes device_name_exists return False
    db.revoke_certificate(serial_number="7777", reason="Retired", scope="CERT_ONLY")
    assert db.device_name_exists("device-req-test") is False


def test_api_token_crud(db):
    import hashlib

    raw_token = "spk_test_secret_1234567890abcdef"
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    token_prefix = raw_token[:8]

    token_id = db.create_api_token(
        name="unifi-guest-portal",
        token_hash=token_hash,
        token_prefix=token_prefix,
        created_by="admin@spoutin.org",
    )
    assert token_id > 0

    tokens = db.list_api_tokens()
    assert len(tokens) == 1
    assert tokens[0]["name"] == "unifi-guest-portal"
    assert tokens[0]["token_prefix"] == token_prefix
    assert "token_hash" not in tokens[0]  # Should not expose hash in list
    assert tokens[0]["last_used_at"] is None

    # Verify and touch
    valid = db.verify_and_touch_token(raw_token)
    assert valid is True

    # Verify last_used_at was updated
    tokens_after = db.list_api_tokens()
    assert tokens_after[0]["last_used_at"] is not None

    # Invalid token fails
    assert db.verify_and_touch_token("spk_invalid_token") is False

    # Revoke token
    revoked = db.revoke_api_token(token_id)
    assert revoked is True

    # After revocation, token no longer verifies
    assert db.verify_and_touch_token(raw_token) is False
    assert len(db.list_api_tokens(active_only=True)) == 0


def test_sync_unifi_guest_sessions(db):
    unifi_guests = [
        {
            "mac": "e6:c9:83:14:3b:07",
            "hostname": "michael-s-s25",
            "start": 1792789010,
            "end": 1792961819,
        },
        {
            "mac": "42:b1:cf:64:00:a0",
            "hostname": "michael-s-tab-s9",
            "start": 1792788950,
            "end": 1792961750,
        },
    ]

    count = db.sync_unifi_guest_sessions(unifi_guests)
    assert count == 2

    sessions = db.list_guest_sessions()
    assert len(sessions) == 2
    assert sessions[0]["mac"] in ["e6:c9:83:14:3b:07", "42:b1:cf:64:00:a0"]
    assert sessions[0]["approved_by"] == "UniFi API"

    # Re-running sync doesn't duplicate existing sessions
    count2 = db.sync_unifi_guest_sessions(unifi_guests)
    assert count2 == 0
    assert len(db.list_guest_sessions()) == 2


