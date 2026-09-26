import time
import pytest
from services.wifi_enrollment.database import CertificateDatabase


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
    assert stats["by_vlan"][8] == 2
