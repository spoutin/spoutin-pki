import pytest
import tempfile
import os
from services.pki.database import CertificateDatabase


@pytest.fixture
def db():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    database = CertificateDatabase(db_path=path)
    yield database
    if os.path.exists(path):
        os.remove(path)


def test_ssh_request_lifecycle(db):
    req_id = db.create_ssh_request(
        name="Adam",
        username="ablack",
        device_name="MacBook",
        public_key="ssh-ed25519 AAAAC3... test",
        key_fingerprint="SHA256:abc123mock",
        principals=["ablack", "root", "operator"],
        ttl="70080h",
    )
    assert req_id is not None
    req = db.get_ssh_request(req_id)
    assert req["status"] == "PENDING"
    assert req["username"] == "ablack"
    assert req["principals"] == "ablack,root,operator"

    pending = db.list_ssh_requests(status="PENDING")
    assert len(pending) == 1
    assert pending[0]["request_id"] == req_id

    db.update_ssh_request_status(req_id, "APPROVED", reviewed_by="slack:U12345")
    updated = db.get_ssh_request(req_id)
    assert updated["status"] == "APPROVED"
    assert updated["reviewed_by"] == "slack:U12345"
    assert updated["reviewed_at"] is not None


def test_ssh_certificate_lifecycle(db):
    db.save_ssh_certificate(
        serial_number="987654321",
        key_id="ablack",
        principals=["ablack", "root", "operator"],
        public_key="ssh-ed25519 AAAAC3... test",
        key_fingerprint="SHA256:abc123mock",
        certificate="ssh-ed25519-cert-v01@openssh.com ... mockcert",
        valid_from=1700000000,
        valid_to=1950000000,
    )
    certs = db.list_ssh_certificates(status="ACTIVE")
    assert len(certs) == 1
    assert certs[0]["serial_number"] == "987654321"
    assert certs[0]["key_id"] == "ablack"
    assert certs[0]["principals"] == "ablack,root,operator"

    revoked = db.revoke_ssh_certificate("987654321")
    assert revoked is True
    assert len(db.list_ssh_certificates(status="ACTIVE")) == 0
    assert len(db.list_ssh_certificates(status="REVOKED")) == 1
