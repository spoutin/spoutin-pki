import datetime
import subprocess
import tempfile
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from services.pki.p12_utils import convert_p12_to_legacy
from services.pki.state_manager import StateManager
from services.pki.models import DevicePlatform, VlanOption
from services.pki.server import create_app
from fastapi.testclient import TestClient


@pytest.fixture
def sample_certs():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-wifi")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(9999)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    pin = "4821"
    modern_p12 = pkcs12.serialize_key_and_certificates(
        b"Spoutin Wi-Fi Certificate",
        key,
        cert,
        None,
        serialization.BestAvailableEncryption(pin.encode("utf-8")),
    )
    return {
        "key": key,
        "cert": cert,
        "pin": pin,
        "modern_p12": modern_p12,
    }


def test_convert_p12_to_legacy(sample_certs):
    modern_bytes = sample_certs["modern_p12"]
    pin = sample_certs["pin"]

    legacy_bytes = convert_p12_to_legacy(modern_bytes, pin, "Spoutin Wi-Fi Certificate")
    assert legacy_bytes is not None
    assert len(legacy_bytes) > 0

    # Ensure it loads back cleanly with the same PIN
    loaded_key, loaded_cert, loaded_cas = pkcs12.load_key_and_certificates(
        legacy_bytes, pin.encode("utf-8")
    )
    assert loaded_key is not None
    assert loaded_cert.serial_number == 9999

    # Verify OpenSSL inspects it as 3DES legacy
    with tempfile.NamedTemporaryFile(suffix=".p12") as tf:
        tf.write(legacy_bytes)
        tf.flush()
        res = subprocess.run(
            ["openssl", "pkcs12", "-info", "-in", tf.name, "-passin", f"pass:{pin}", "-noout"],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0
        info_output = res.stdout + res.stderr
        assert "pbeWithSHA1And3-KeyTripleDES-CBC" in info_output
        assert "PBES2" not in info_output


def test_state_manager_legacy_download(sample_certs):
    sm = StateManager()
    req = sm.create_request("samsung-s10", DevicePlatform.ANDROID, "10.0.0.50")
    
    token, pin = sm.approve_request(
        request_id=req.request_id,
        approved_name="samsung-s10",
        vlan=VlanOption.SEMI_PRIVATE,
        p12_bytes=sample_certs["modern_p12"],
        pin=sample_certs["pin"],
        serial_number="9999",
    )

    # Standard download
    data_std, fn_std = sm.get_download(token, legacy=False)
    assert fn_std == "samsung-s10.p12"
    assert data_std == sample_certs["modern_p12"]

    # Legacy download via token
    data_leg, fn_leg = sm.get_download(token, legacy=True)
    assert fn_leg == "samsung-s10-legacy.p12"
    assert data_leg != sample_certs["modern_p12"]
    
    # Verify legacy decrypts
    l_key, l_cert, _ = pkcs12.load_key_and_certificates(data_leg, pin.encode("utf-8"))
    assert l_cert.serial_number == 9999

    # Legacy download via serial
    data_ser, fn_ser = sm.get_download_by_serial("9999", legacy=True)
    assert fn_ser == "samsung-s10-legacy.p12"
    s_key, s_cert, _ = pkcs12.load_key_and_certificates(data_ser, pin.encode("utf-8"))
    assert s_cert.serial_number == 9999


def test_download_endpoint_legacy_parameter(sample_certs, tmp_path):
    sm = StateManager()
    db_file = tmp_path / "test.db"
    from services.pki.database import CertificateDatabase
    from services.pki.auth import create_session_token
    db = CertificateDatabase(str(db_file))

    app = create_app(state_manager=sm, database=db)
    client = TestClient(app)

    req = sm.create_request("galaxy-s10", DevicePlatform.ANDROID, "10.0.0.51")
    token, pin = sm.approve_request(
        request_id=req.request_id,
        approved_name="galaxy-s10",
        vlan=VlanOption.SEMI_PRIVATE,
        p12_bytes=sample_certs["modern_p12"],
        pin=sample_certs["pin"],
        serial_number="9999",
    )
    db.insert_certificate(
        serial_number="9999",
        device_name="galaxy-s10",
        platform="android",
        vlan_id=8,
        vlan_label="8 - SemiPrivate",
        client_ip="10.0.0.51",
        cert_pem="DUMMY_PEM",
        issued_at=1000,
        expires_at=2000,
        pin=pin,
    )

    # Standard download
    resp_std = client.get(f"/api/download/{token}")
    assert resp_std.status_code == 200
    assert 'filename="galaxy-s10.p12"' in resp_std.headers.get("Content-Disposition", "")
    assert resp_std.content == sample_certs["modern_p12"]

    # Legacy download
    resp_leg = client.get(f"/api/download/{token}?legacy=true")
    assert resp_leg.status_code == 200
    assert 'filename="galaxy-s10-legacy.p12"' in resp_leg.headers.get("Content-Disposition", "")
    assert resp_leg.content != sample_certs["modern_p12"]

    # Decrypt and verify
    k, c, _ = pkcs12.load_key_and_certificates(resp_leg.content, pin.encode("utf-8"))
    assert c.serial_number == 9999

    # Admin download legacy test
    app.state.session_secret_key = "test-secret-key-32-chars-long!!"
    app.state.allowed_admin_emails = "admin@spoutin.org"
    admin_token = create_session_token("admin@spoutin.org", "Admin", secret_key="test-secret-key-32-chars-long!!")
    client.cookies.set("wifi_admin_session", admin_token)
    adm_leg = client.get("/api/admin/certificates/9999/download?legacy=true")
    assert adm_leg.status_code == 200
    assert 'filename="galaxy-s10-legacy.p12"' in adm_leg.headers.get("Content-Disposition", "")
    k_adm, c_adm, _ = pkcs12.load_key_and_certificates(adm_leg.content, pin.encode("utf-8"))
    assert c_adm.serial_number == 9999
