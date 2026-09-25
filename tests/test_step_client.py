import datetime
from unittest.mock import MagicMock, patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from services.wifi_enrollment.step_client import StepCaClient


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


def test_generate_key_and_csr():
    client = StepCaClient(
        ca_url="https://127.0.0.1:9000",
        domain="int.spoutin.org",
    )
    key, csr_pem = client.generate_key_and_csr("ablack-phone")

    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 2048

    csr = x509.load_pem_x509_csr(csr_pem)
    assert csr.is_signature_valid is True
    cn = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    assert cn == "ablack-phone"

    sans = csr.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    dns_names = sans.get_values_for_type(x509.DNSName)
    assert "ablack-phone" in dns_names
    assert "ablack-phone.int.spoutin.org" in dns_names


def test_build_p12_bundle():
    client = StepCaClient(ca_url="https://127.0.0.1:9000")

    root_cert, _ = _generate_self_signed_cert("Root CA", is_ca=True)
    inter_cert, _ = _generate_self_signed_cert("Intermediate CA", is_ca=True)
    leaf_cert, leaf_key = _generate_self_signed_cert("ablack-phone", is_ca=False)

    root_pem = root_cert.public_bytes(serialization.Encoding.PEM)
    inter_pem = inter_cert.public_bytes(serialization.Encoding.PEM)
    leaf_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)

    pin = "4829"
    p12_bytes = client.build_p12_bundle(
        private_key=leaf_key,
        cert_pem=leaf_pem,
        intermediate_pem=inter_pem,
        root_pem=root_pem,
        pin=pin,
        friendly_name="ablack-phone",
    )

    assert p12_bytes is not None
    assert len(p12_bytes) > 0

    # Verify we can decrypt and unpack with the PIN
    unpacked_key, unpacked_cert, unpacked_cas = pkcs12.load_key_and_certificates(
        p12_bytes, pin.encode("utf-8")
    )

    assert unpacked_cert.subject == leaf_cert.subject
    assert len(unpacked_cas) == 2
    assert unpacked_key.private_numbers() == leaf_key.private_numbers()


@patch("requests.Session.post")
def test_sign_csr_success(mock_post):
    leaf_cert, _ = _generate_self_signed_cert("ablack-phone")
    inter_cert, _ = _generate_self_signed_cert("Intermediate CA")
    leaf_pem_str = leaf_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    inter_pem_str = inter_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {
        "serverPem": leaf_pem_str,
        "caPem": inter_pem_str,
        "certChainPem": [inter_pem_str],
    }
    mock_post.return_value = mock_resp

    client = StepCaClient(ca_url="https://127.0.0.1:9000")
    leaf_out, chain_out = client.sign_csr(
        csr_pem=b"dummy_csr",
        ott_token="dummy_jwt_token",
    )

    assert leaf_out.startswith(b"-----BEGIN CERTIFICATE-----")
    assert len(chain_out) == 1
