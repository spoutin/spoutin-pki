import pytest
from unittest.mock import MagicMock
from services.pki.slack_handler import SlackEnrollmentHandler


@pytest.fixture
def mock_handler():
    mock_app = MagicMock()
    mock_app.client.chat_postMessage.return_value = {"ok": True, "ts": "1700000000.123456", "channel": "C12345"}
    mock_sm = MagicMock()
    mock_ca = MagicMock()
    mock_ca.sign_ssh_public_key.return_value = {
        "serial_number": "999111",
        "signed_key": "ssh-ed25519-cert-v01@openssh.com AAAA... mockcert",
    }
    mock_db = MagicMock()
    mock_db.get_ssh_request.return_value = {
        "request_id": "ssh-req-123",
        "name": "Adam",
        "username": "ablack",
        "device_name": "MacBook Air",
        "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBXtest",
        "key_fingerprint": "SHA256:abc123mock",
        "principals": "ablack,root,operator",
        "requested_ttl": "70080h",
        "status": "PENDING",
    }

    handler = SlackEnrollmentHandler(
        app=mock_app,
        state_manager=mock_sm,
        ca_client=mock_ca,
        channel_id="C12345",
        database=mock_db,
    )
    return handler


def test_send_ssh_request_notification(mock_handler):
    ts = mock_handler.send_ssh_request_notification(
        request_id="ssh-req-123",
        name="Adam",
        username="ablack",
        device_name="MacBook Air",
        fingerprint="SHA256:abc123mock",
        principals=["ablack", "root", "operator"],
    )
    assert ts == "1700000000.123456"
    mock_handler.app.client.chat_postMessage.assert_called_once()
    args, kwargs = mock_handler.app.client.chat_postMessage.call_args
    assert kwargs["channel"] == "C12345"
    assert "SSH Key Signing Request" in kwargs["text"]


def test_ssh_quick_approve_action(mock_handler):
    # Verify action decorators were called
    mock_handler.app.action.assert_any_call("ssh_quick_approve")
    mock_handler.app.action.assert_any_call("ssh_open_edit_modal")
    mock_handler.app.action.assert_any_call("ssh_reject")
    mock_handler.app.view.assert_any_call("submit_ssh_edit_approval")


def test_build_ssh_edit_modal(mock_handler):
    req = {
        "request_id": "ssh-req-123",
        "username": "ablack",
        "device_name": "MacBook",
        "principals": "ablack,root,operator",
        "requested_ttl": "70080h",
    }
    modal = mock_handler.build_ssh_edit_modal(req)
    assert modal["type"] == "modal"
    assert modal["callback_id"] == "submit_ssh_edit_approval"
    block_ids = [b["block_id"] for b in modal["blocks"]]
    assert "key_id_block" in block_ids
    assert "device_name_block" in block_ids
    assert "principals_block" in block_ids
    assert "ttl_block" in block_ids
