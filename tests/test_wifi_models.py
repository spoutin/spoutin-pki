import pytest
from pydantic import ValidationError
from services.pki.models import (
    DevicePlatform,
    EnrollmentRequest,
    VlanOption,
    sanitize_device_name,
)


def test_vlan_options():
    assert VlanOption.SEMI_PRIVATE.value == 8
    assert VlanOption.LAN.value == 1
    assert VlanOption.DMS.value == 2
    assert VlanOption.IOT.value == 9
    assert VlanOption.default() == VlanOption.SEMI_PRIVATE
    assert "SemiPrivate" in VlanOption.SEMI_PRIVATE.label


def test_sanitize_device_name():
    assert sanitize_device_name("Adam's Phone") == "adams-phone"
    assert sanitize_device_name("iPhone_15_Pro") == "iphone-15-pro"
    assert sanitize_device_name("my-laptop") == "my-laptop"
    assert sanitize_device_name("  Pixel  8  ") == "pixel-8"
    assert sanitize_device_name("-leading-and-trailing-") == "leading-and-trailing"


def test_valid_enrollment_request():
    req = EnrollmentRequest(device_name="ablack-phone", platform=DevicePlatform.ANDROID)
    assert req.device_name == "ablack-phone"
    assert req.platform == DevicePlatform.ANDROID

    # Auto-sanitization
    req2 = EnrollmentRequest(device_name="Ablack Phone", platform="ios")
    assert req2.device_name == "ablack-phone"
    assert req2.platform == DevicePlatform.IOS


def test_invalid_device_names():
    # Reserved name
    with pytest.raises(ValidationError) as exc:
        EnrollmentRequest(device_name="admin", platform=DevicePlatform.MACOS)
    assert "reserved" in str(exc.value).lower()

    # Too short
    with pytest.raises(ValidationError):
        EnrollmentRequest(device_name="a", platform=DevicePlatform.MACOS)

    # Empty after sanitizing hyphens/symbols
    with pytest.raises(ValidationError):
        EnrollmentRequest(device_name="---", platform=DevicePlatform.MACOS)

    # Too long (>32 chars)
    with pytest.raises(ValidationError):
        EnrollmentRequest(device_name="a" * 33, platform=DevicePlatform.MACOS)

    # Invalid special chars that reduce to empty
    with pytest.raises(ValidationError):
        EnrollmentRequest(device_name="$$$", platform=DevicePlatform.MACOS)


def test_resolve_env_files():
    from services.pki.config import _resolve_env_files
    files = _resolve_env_files()
    assert ".env" in files
    assert "config.env" in files
    assert "/etc/wifi-enrollment/config.env" in files
