import time
import pytest
from services.wifi_enrollment.models import DevicePlatform, EnrollmentStatus, VlanOption
from services.wifi_enrollment.state_manager import StateManager


def test_create_and_get_request():
    sm = StateManager(ttl_seconds=60, max_pending=5)
    record = sm.create_request("ablack-phone", DevicePlatform.ANDROID, "192.168.1.50")

    assert record.device_name == "ablack-phone"
    assert record.status == EnrollmentStatus.PENDING
    assert record.client_ip == "192.168.1.50"

    fetched = sm.get_request(record.request_id)
    assert fetched is not None
    assert fetched.request_id == record.request_id


def test_max_pending_requests():
    sm = StateManager(ttl_seconds=60, max_pending=2)
    sm.create_request("device1", DevicePlatform.IOS, "192.168.1.1")
    sm.create_request("device2", DevicePlatform.IOS, "192.168.1.2")

    with pytest.raises(ValueError) as exc:
        sm.create_request("device3", DevicePlatform.IOS, "192.168.1.3")
    assert "maximum" in str(exc.value).lower()


def test_approve_request_and_consume_download():
    sm = StateManager(ttl_seconds=60)
    record = sm.create_request("ablack-phone", DevicePlatform.ANDROID, "192.168.1.50")

    dummy_p12 = b"dummy_pkcs12_content"
    token, pin = sm.approve_request(
        request_id=record.request_id,
        approved_name="ablack-phone",
        vlan=VlanOption.SEMI_PRIVATE,
        p12_bytes=dummy_p12,
    )

    assert len(pin) == 4
    assert pin.isdigit()
    assert token is not None

    req = sm.get_request(record.request_id)
    assert req.status == EnrollmentStatus.APPROVED
    assert req.pin == pin
    assert req.download_token == token

    # Consume download
    p12_out, filename = sm.consume_download(token)
    assert p12_out == dummy_p12
    assert filename == "ablack-phone.p12"

    # Second download attempt must fail (single-use)
    assert sm.consume_download(token) is None


def test_reject_request():
    sm = StateManager(ttl_seconds=60)
    record = sm.create_request("ablack-phone", DevicePlatform.ANDROID, "192.168.1.50")

    success = sm.reject_request(record.request_id, reason="Device unrecognized")
    assert success is True

    req = sm.get_request(record.request_id)
    assert req.status == EnrollmentStatus.REJECTED
    assert "unrecognized" in req.error_message


def test_request_expiration():
    sm = StateManager(ttl_seconds=1)
    record = sm.create_request("ablack-phone", DevicePlatform.ANDROID, "192.168.1.50")

    time.sleep(1.1)
    req = sm.get_request(record.request_id)
    assert req.status == EnrollmentStatus.EXPIRED

    # Clean up
    cleaned = sm.cleanup_expired()
    assert cleaned >= 1
    assert sm.get_request(record.request_id) is None
