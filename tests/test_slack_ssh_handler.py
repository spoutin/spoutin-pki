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

    # Find registered handler for ssh_quick_approve
    handlers = {}
    for i, call in enumerate(mock_handler.app.action.call_args_list):
        action_name = call[0][0]
        handler_fn = mock_handler.app.action.return_value.call_args_list[i][0][0]
        handlers[action_name] = handler_fn

    quick_approve_fn = handlers["ssh_quick_approve"]
    ack = MagicMock()
    body = {
        "actions": [{"value": "ssh-req-123"}],
        "user": {"username": "adminuser"},
        "channel": {"id": "C12345"},
        "message": {"ts": "1700000000.123456"},
    }
    quick_approve_fn(ack, body)
    ack.assert_called_once()
    mock_handler.database.update_ssh_request_status.assert_called_once_with(
        "ssh-req-123",
        "APPROVED",
        reviewed_by="slack:@adminuser",
        certificate="ssh-ed25519-cert-v01@openssh.com AAAA... mockcert",
        serial_number="999111",
    )


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


def test_ssh_modal_submission_execution(mock_handler):
    modal_submit_fn = mock_handler.app.view.return_value.call_args[0][0]
    ack = MagicMock()
    body = {"user": {"username": "adminuser"}}
    view = {
        "private_metadata": '{"request_id": "ssh-req-123", "slack_channel": "C12345", "slack_ts": "1700000000.123456"}',
        "state": {
            "values": {
                "key_id_block": {"key_id_input": {"value": "ablack"}},
                "device_name_block": {"device_name_input": {"value": "MacBook Air"}},
                "principals_block": {"principals_input": {"value": "ablack,root"}},
                "key_filename_block": {"key_filename_input": {"value": "id_ed25519"}},
                "ttl_block": {"ttl_input": {"value": "70080h"}},
            }
        },
    }
    modal_submit_fn(ack, body, view)
    ack.assert_called_once()
    mock_handler.database.update_ssh_request_status.assert_called_once_with(
        "ssh-req-123",
        "APPROVED",
        reviewed_by="slack:@adminuser",
        certificate="ssh-ed25519-cert-v01@openssh.com AAAA... mockcert",
        serial_number="999111",
    )
