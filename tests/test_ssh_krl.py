import pytest
import tempfile
import subprocess
import os
import hashlib
from fastapi.testclient import TestClient
from unittest.mock import MagicMock
from services.pki.server import create_app
from services.pki.database import CertificateDatabase
from services.pki.krl import generate_krl, format_revoked_keys_text, KrlManager


@pytest.fixture
def test_keys():
    """Generates an ephemeral CA keypair and user keypair for testing KRLs."""
    with tempfile.TemporaryDirectory() as td:
        ca_path = os.path.join(td, "ca")
        user_path = os.path.join(td, "user")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", ca_path, "-N", ""], check=True, capture_output=True)
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", user_path, "-N", ""], check=True, capture_output=True)

        with open(ca_path + ".pub") as f:
            ca_pub = f.read().strip()
        with open(user_path + ".pub") as f:
            user_pub = f.read().strip()

        # Sign cert 1 (serial 1001)
        cert1_path = os.path.join(td, "cert1.pub")
        subprocess.run(
            ["ssh-keygen", "-s", ca_path, "-I", "user1", "-n", "root", "-z", "1001", user_path + ".pub"],
            check=True,
            capture_output=True,
        )
        os.rename(user_path + "-cert.pub", cert1_path)
        with open(cert1_path) as f:
            cert1_str = f.read().strip()

        # Sign cert 2 (serial 1002)
        cert2_path = os.path.join(td, "cert2.pub")
        subprocess.run(
            ["ssh-keygen", "-s", ca_path, "-I", "user2", "-n", "root", "-z", "1002", user_path + ".pub"],
            check=True,
            capture_output=True,
        )
        os.rename(user_path + "-cert.pub", cert2_path)
        with open(cert2_path) as f:
            cert2_str = f.read().strip()

        yield {
            "ca_pub": ca_pub,
            "user_pub": user_pub,
            "cert1_str": cert1_str,
            "cert1_path": cert1_path,
            "cert2_str": cert2_str,
            "cert2_path": cert2_path,
        }


def test_empty_krl_generation(test_keys):
    """Verifies that an empty KRL is valid binary structure and passes validation."""
    krl_bytes = generate_krl(test_keys["ca_pub"], [])
    assert len(krl_bytes) >= 16
    assert krl_bytes.startswith(b"SSHKRL\n")

    with tempfile.NamedTemporaryFile(suffix=".krl") as tf:
        tf.write(krl_bytes)
        tf.flush()
        # ssh-keygen -Q should exit 0 (ok, cert1 is not revoked)
        res = subprocess.run(["ssh-keygen", "-Q", "-f", tf.name, test_keys["cert1_path"]], capture_output=True, text=True)
        assert res.returncode == 0
        assert "ok" in res.stdout


def test_krl_with_revoked_serial(test_keys):
    """Verifies that revoked serials in the KRL are recognized as REVOKED by ssh-keygen."""
    revoked_list = [
        {
            "serial_number": "1001",
            "key_id": "user1",
            "public_key": test_keys["user_pub"],
            "certificate": test_keys["cert1_str"],
        }
    ]
    krl_bytes = generate_krl(test_keys["ca_pub"], revoked_list)
    assert krl_bytes.startswith(b"SSHKRL\n")

    with tempfile.NamedTemporaryFile(suffix=".krl") as tf:
        tf.write(krl_bytes)
        tf.flush()
        # cert1 (serial 1001) should be REVOKED (rc=1)
        res1 = subprocess.run(["ssh-keygen", "-Q", "-f", tf.name, test_keys["cert1_path"]], capture_output=True, text=True)
        assert res1.returncode == 1
        assert "REVOKED" in res1.stdout

        # cert2 (serial 1002) should be ok (rc=0)
        res2 = subprocess.run(["ssh-keygen", "-Q", "-f", tf.name, test_keys["cert2_path"]], capture_output=True, text=True)
        assert res2.returncode == 0
        assert "ok" in res2.stdout


def test_format_revoked_keys_text(test_keys):
    """Verifies plain-text revoked-keys formatter."""
    revoked_list = [
        {
            "serial_number": "1001",
            "key_id": "user1",
            "public_key": test_keys["user_pub"],
            "certificate": test_keys["cert1_str"],
        }
    ]
    text = format_revoked_keys_text(revoked_list)
    assert "# Spoutin PKI OpenSSH Revoked Keys" in text
    assert "Serial: 1001" in text
    assert test_keys["cert1_str"] in text


def test_ssh_krl_endpoints(test_keys):
    """Tests the GET /ssh-krl and GET /ssh-revoked-keys endpoints."""
    fd, db_path = tempfile.mkstemp()
    os.close(fd)
    try:
        db = CertificateDatabase(db_path=db_path)
        # Seed one revoked cert
        db.save_ssh_certificate(
            serial_number="1001",
            key_id="user1",
            principals=["root"],
            public_key=test_keys["user_pub"],
            key_fingerprint="SHA256:mockfingerprint",
            certificate=test_keys["cert1_str"],
            valid_from=1700000000,
            valid_to=1950000000,
        )
        db.revoke_ssh_certificate("1001")

        mock_ca = MagicMock()
        mock_ca.get_ssh_ca_public_key.return_value = test_keys["ca_pub"]

        app = create_app(database=db, ca_client=mock_ca)
        client = TestClient(app)

        # 1. GET /ssh-krl
        resp_krl = client.get("/ssh-krl")
        assert resp_krl.status_code == 200
        assert resp_krl.headers["content-type"] == "application/octet-stream"
        assert resp_krl.content.startswith(b"SSHKRL\n")
        etag = resp_krl.headers.get("etag")
        assert etag is not None

        # Conditional GET with matching ETag -> 304
        resp_304 = client.get("/ssh-krl", headers={"if-none-match": etag})
        assert resp_304.status_code == 304

        # 2. GET /ssh-revoked-keys
        resp_text = client.get("/ssh-revoked-keys")
        assert resp_text.status_code == 200
        assert "text/plain" in resp_text.headers["content-type"]
        assert test_keys["cert1_str"] in resp_text.text
        text_etag = resp_text.headers.get("etag")
        assert text_etag is not None

        resp_text_304 = client.get("/ssh-revoked-keys", headers={"if-none-match": text_etag})
        assert resp_text_304.status_code == 304

        # 3. Revoke cert2 via admin endpoint and verify KRL updates with new ETag
        app.state.session_secret_key = "test-secret"
        app.state.allowed_admin_emails = "admin@spoutin.org"
        from services.pki.auth import create_session_token
        admin_cookie = {"wifi_admin_session": create_session_token("admin@spoutin.org", "Adam", secret_key="test-secret")}

        db.save_ssh_certificate(
            serial_number="1002",
            key_id="user2",
            principals=["root"],
            public_key=test_keys["user_pub"],
            key_fingerprint="SHA256:mock2",
            certificate=test_keys["cert2_str"],
            valid_from=1700000000,
            valid_to=1950000000,
        )
        revoke_resp = client.post("/api/admin/ssh/certificates/1002/revoke", cookies=admin_cookie)
        assert revoke_resp.status_code == 200

        # Next GET /ssh-krl should have a different ETag and revoke cert2
        resp_krl2 = client.get("/ssh-krl")
        assert resp_krl2.status_code == 200
        new_etag = resp_krl2.headers.get("etag")
        assert new_etag != etag

        with tempfile.NamedTemporaryFile(suffix=".krl") as tf:
            tf.write(resp_krl2.content)
            tf.flush()
            # cert2 should now be REVOKED (rc=1)
            q_res = subprocess.run(["ssh-keygen", "-Q", "-f", tf.name, test_keys["cert2_path"]], capture_output=True, text=True)
            assert q_res.returncode == 1
            assert "REVOKED" in q_res.stdout
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)
