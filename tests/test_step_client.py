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
        "crt": leaf_pem_str,
        "ca": inter_pem_str,
        "certChain": [leaf_pem_str, inter_pem_str],
    }
    mock_post.return_value = mock_resp

    client = StepCaClient(ca_url="https://127.0.0.1:9000")
    leaf_out, chain_out = client.sign_csr(
        csr_pem=b"dummy_csr",
        ott_token="dummy_jwt_token",
    )

    assert leaf_out.startswith(b"-----BEGIN CERTIFICATE-----")
    assert len(chain_out) == 2


def test_pure_python_token_generation():
    from cryptography.hazmat.primitives.asymmetric import ec
    from services.wifi_enrollment.step_client import base64url_decode

    # Create EC P-256 test key
    ec_key = ec.generate_private_key(ec.SECP256R1())
    client = StepCaClient(
        ca_url="https://127.0.0.1:9000",
        domain="int.spoutin.org",
        provisioner_name="admin@int.spoutin.org",
        provisioner_private_key=ec_key,
        provisioner_kid="test-kid-12345",
    )

    token = client.generate_provisioner_token("ablack-phone")
    assert token is not None

    parts = token.split(".")
    assert len(parts) == 3

    import json
    header = json.loads(base64url_decode(parts[0]))
    payload = json.loads(base64url_decode(parts[1]))

    assert header["alg"] == "ES256"
    assert header["kid"] == "test-kid-12345"
    assert header["typ"] == "JWT"

    assert payload["iss"] == "admin@int.spoutin.org"
    assert payload["sub"] == "ablack-phone"
    assert "step-certificate-authority" in payload["aud"]
    assert "https://step-ca.int.spoutin.org/1.0/sign" in payload["aud"]
    assert "ablack-phone" in payload["sans"]
    assert "ablack-phone.int.spoutin.org" in payload["sans"]


def test_decrypt_jwe_key():
    import json
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.keywrap import aes_key_wrap
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from services.wifi_enrollment.step_client import base64url_encode, decrypt_jwe_key

    priv_key = ec.generate_private_key(ec.SECP256R1())
    d_bytes = priv_key.private_numbers().private_value.to_bytes(32, "big")
    d_b64 = base64url_encode(d_bytes)
    jwk_json = json.dumps({"kty": "EC", "crv": "P-256", "d": d_b64})

    password = "secretpassword"
    p2s = b"1234567890123456"
    p2c = 1000
    salt = b"PBES2-HS256+A128KW\x00" + p2s
    kek = PBKDF2HMAC(hashes.SHA256(), length=16, salt=salt, iterations=p2c).derive(password.encode("utf-8"))
    cek = AESGCM.generate_key(bit_length=256)
    enc_key = aes_key_wrap(kek, cek)
    iv = b"123456789012"
    header = {"alg": "PBES2-HS256+A128KW", "enc": "A256GCM", "p2c": p2c, "p2s": base64url_encode(p2s)}
    header_b64 = base64url_encode(json.dumps(header))
    ct_tag = AESGCM(cek).encrypt(iv, jwk_json.encode("utf-8"), header_b64.encode("ascii"))
    ct = ct_tag[:-16]
    tag = ct_tag[-16:]

    jwe = f"{header_b64}.{base64url_encode(enc_key)}.{base64url_encode(iv)}.{base64url_encode(ct)}.{base64url_encode(tag)}"

    recovered_key = decrypt_jwe_key(jwe, password)
    assert recovered_key.private_numbers().private_value == priv_key.private_numbers().private_value
