import datetime
import time
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from services.wifi_enrollment.openbao_client import OpenBaoCaClient


def _generate_self_signed_cert(cn: str, is_ca: bool = False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=365)
        )
    )
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
    cert = builder.sign(key, hashes.SHA256())
    return cert, key


def test_openbao_approle_auth():
    client = OpenBaoCaClient(
        base_url="http://127.0.0.1:8200",
        role_id="test-role-id",
        secret_id="test-secret-id",
    )

    with patch.object(client.session, "post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "auth": {
                "client_token": "s.bao-token-12345",
                "lease_duration": 3600,
            }
        }
        mock_post.return_value = mock_resp

        token = client._ensure_authenticated()
        assert token == "s.bao-token-12345"
        assert client._cached_token == "s.bao-token-12345"

        # Calling again should use cached token
        token2 = client._ensure_authenticated()
        assert token2 == "s.bao-token-12345"
        mock_post.assert_called_once()
        assert "v1/auth/approle/login" in mock_post.call_args[0][0]


def test_openbao_static_token():
    client = OpenBaoCaClient(
        base_url="http://127.0.0.1:8200",
        token="s.static-root-token",
    )
    token = client._ensure_authenticated()
    assert token == "s.static-root-token"


def test_openbao_generate_key_and_csr():
    client = OpenBaoCaClient(domain="int.spoutin.org")
    key, csr_pem = client.generate_key_and_csr("test-bao-device")

    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 2048

    csr = x509.load_pem_x509_csr(csr_pem)
    assert csr.is_signature_valid is True
    cn = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    assert cn == "test-bao-device"

    sans = csr.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    dns_names = sans.get_values_for_type(x509.DNSName)
    assert "test-bao-device" in dns_names
    assert "test-bao-device.int.spoutin.org" in dns_names


def test_openbao_sign_csr():
    client = OpenBaoCaClient(
        base_url="http://127.0.0.1:8200",
        token="s.valid-token",
        pki_mount="pki",
        role_name="wifi-client",
    )

    cert, _ = _generate_self_signed_cert("test-device")
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    ca_cert, _ = _generate_self_signed_cert("Spoutin Root CA", is_ca=True)
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    with patch.object(client.session, "post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "certificate": cert_pem,
                "issuing_ca": ca_pem,
                "ca_chain": [ca_pem],
                "serial_number": "12:34:56:78:ab:cd",
            }
        }
        mock_post.return_value = mock_resp

        leaf, chain, cert_id, serial = client.sign_csr(b"fake-csr-bytes")
        assert leaf == cert_pem
        assert len(chain) == 1
        assert cert_id is None
        assert serial == "12345678abcd"
        mock_post.assert_called_once()
        assert "v1/pki/sign/wifi-client" in mock_post.call_args[0][0]
        assert mock_post.call_args[1]["headers"]["X-Vault-Token"] == "s.valid-token"


def test_openbao_build_p12_bundle():
    client = OpenBaoCaClient()

    cert, key = _generate_self_signed_cert("my-phone")
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    ca_cert, _ = _generate_self_signed_cert("Spoutin Root CA", is_ca=True)
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)

    p12_bytes = client.build_p12_bundle(
        private_key=key,
        cert_pem=cert_pem,
        chain_pems=[ca_pem],
        pin="5678",
        friendly_name="Spoutin Wi-Fi Certificate",
    )

    assert p12_bytes is not None
    assert len(p12_bytes) > 0

    dec_key, dec_cert, dec_cas = pkcs12.load_key_and_certificates(p12_bytes, b"5678")
    assert dec_key is not None
    assert dec_cert.serial_number == cert.serial_number
    assert len(dec_cas) == 1
    assert dec_cas[0].serial_number == ca_cert.serial_number


def test_openbao_revoke_certificate():
    client = OpenBaoCaClient(
        base_url="http://127.0.0.1:8200",
        token="s.valid-token",
        pki_mount="pki",
    )

    with patch.object(client.session, "post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        result = client.revoke_certificate("12345678abcd", reason=0)
        assert result is True
        mock_post.assert_called_once()
        assert "v1/pki/revoke" in mock_post.call_args[0][0]
        assert mock_post.call_args[1]["json"]["serial_number"] == "12345678abcd"


def test_openbao_get_crl():
    client = OpenBaoCaClient(
        base_url="http://127.0.0.1:8200",
        token="s.valid-token",
        pki_mount="pki",
    )

    fake_crl = b"-----BEGIN X509 CRL-----\nMIIB...\n-----END X509 CRL-----"
    with patch.object(client.session, "get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.content = fake_crl
        mock_get.return_value = mock_resp

        crl_out = client.get_crl(as_pem=True)
        assert crl_out == fake_crl
        mock_get.assert_called_once()
        assert "v1/pki/crl/pem" in mock_get.call_args[0][0]
