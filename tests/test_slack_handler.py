import datetime
from unittest.mock import MagicMock
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from services.wifi_enrollment.models import DevicePlatform, EnrollmentStatus, VlanOption
from services.wifi_enrollment.slack_handler import SlackEnrollmentHandler
from services.wifi_enrollment.state_manager import StateManager


@pytest.fixture
def mock_clients():
    step_client = MagicMock()
    step_client.generate_key_and_csr.return_value = (MagicMock(), b"dummy_csr")
    step_client.generate_provisioner_token.return_value = "dummy_jwt"
    step_client.sign_csr.return_value = (b"dummy_leaf_cert", [b"dummy_inter_cert"])
    step_client.build_p12_bundle.return_value = b"dummy_p12_data"

    radius_client = MagicMock()
    radius_client.user_exists.return_value = False
    radius_client.add_user.return_value = {"result": "saved"}
    radius_client.reconfigure_service.return_value = True

    slack_app = MagicMock()
    state_manager = StateManager(ttl_seconds=300)

    handler = SlackEnrollmentHandler(
        app=slack_app,
        state_manager=state_manager,
        step_client=step_client,
        radius_client=radius_client,
        channel_id="C12345",
    )
    return handler, state_manager, step_client, radius_client


def test_build_enrollment_blocks(mock_clients):
    handler, sm, _, _ = mock_clients
    record = sm.create_request("ablack-phone", DevicePlatform.ANDROID, "192.168.1.50")

    blocks = handler.build_enrollment_blocks(record)
    assert len(blocks) >= 3

    # Verify Target VLAN field exists in the section
    section_block = [b for b in blocks if b.get("type") == "section"][0]
    field_texts = [f.get("text", "") for f in section_block.get("fields", [])]
    assert any("Target VLAN" in t for t in field_texts)
    assert any("SemiPrivate" in t for t in field_texts)

    # Verify action buttons exist
    action_block = [b for b in blocks if b.get("type") == "actions"][0]
    elements = action_block.get("elements", [])
    action_ids = [elem.get("action_id") for elem in elements]
    assert "quick_approve" in action_ids
    assert "open_edit_modal" in action_ids
    assert "reject_request" in action_ids

    # Verify Quick Approve button text has the cleaner "⚡ Quick Approve" label
    quick_btn = [elem for elem in elements if elem.get("action_id") == "quick_approve"][0]
    assert quick_btn["text"]["text"] == "⚡ Quick Approve"


def test_build_edit_modal(mock_clients):
    handler, sm, _, _ = mock_clients
    record = sm.create_request("ablack-phone", DevicePlatform.ANDROID, "192.168.1.50")

    modal = handler.build_edit_modal(record)
    assert modal.get("type") == "modal"
    assert modal.get("callback_id") == "submit_edit_approval"
    blocks = modal.get("blocks", [])
    block_ids = [b.get("block_id") for b in blocks]
    assert "device_name_block" in block_ids
    assert "vlan_block" in block_ids


def test_validate_modal_submission_duplicate(mock_clients):
    handler, sm, _, radius_client = mock_clients
    record = sm.create_request("ablack-phone", DevicePlatform.ANDROID, "192.168.1.50")

    # Set duplicate check to true
    radius_client.user_exists.return_value = True

    errors = handler.validate_modal_submission(
        device_name="ablack-phone",
        allow_overwrite=False,
    )
    assert "device_name_block" in errors
    assert "already exists" in errors["device_name_block"]

    # When overwrite is enabled, duplicate should not return an error
    errors_allowed = handler.validate_modal_submission(
        device_name="ablack-phone",
        allow_overwrite=True,
    )
    assert errors_allowed == {}


def test_process_approval_flow(mock_clients):
    handler, sm, step_client, radius_client = mock_clients
    record = sm.create_request("ablack-phone", DevicePlatform.ANDROID, "192.168.1.50")

    token, pin = handler.process_approval(
        request_id=record.request_id,
        approved_name="ablack-phone",
        vlan=VlanOption.SEMI_PRIVATE,
    )

    assert len(pin) == 4
    assert token is not None

    # Verify step-ca was called
    step_client.generate_key_and_csr.assert_called_once_with("ablack-phone")
    step_client.sign_csr.assert_called_once()
    step_client.build_p12_bundle.assert_called_once()

    # Verify FreeRADIUS was called
    radius_client.upsert_user.assert_called_once_with(
        username="ablack-phone",
        vlan=8,
        description=f"Spoutin PKI | vlan:8 | req:{record.request_id}",
    )
    radius_client.reconfigure_service.assert_called_once()

    # Verify state manager was updated
    updated_rec = sm.get_request(record.request_id)
    assert updated_rec.status == EnrollmentStatus.APPROVED
    assert updated_rec.pin == pin


def test_update_channel_error_blocks(mock_clients):
    handler, sm, _, _ = mock_clients
    record = sm.create_request("ablack-phone", DevicePlatform.ANDROID, "192.168.1.50")

    handler._update_channel_error(
        channel="C123",
        ts="123.456",
        record=record,
        error_msg="step-ca sign failed (HTTP 401): invalid jwk token audience claim",
        user_name="spoutin",
        vlan=VlanOption.SEMI_PRIVATE,
    )

    handler.app.client.chat_update.assert_called_once()
    call_args = handler.app.client.chat_update.call_args.kwargs
    assert call_args["channel"] == "C123"
    assert call_args["ts"] == "123.456"
    assert "Approval failed" in call_args["text"]

    blocks = call_args["blocks"]
    assert any("Wi-Fi Enrollment Failed" in str(b) for b in blocks)
    assert any("invalid jwk token audience claim" in str(b) for b in blocks)


def test_process_approval_flow_infisical():
    app = MagicMock()
    sm = StateManager(ttl_seconds=300)
    infisical_client = MagicMock()
    radius_client = MagicMock()

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test-inf-dev")]))
        .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test CA")]))
        .public_key(key.public_key())
        .serial_number(123456789)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    infisical_client.generate_key_and_csr.return_value = (key, b"fake-csr")
    infisical_client.sign_csr.return_value = (cert_pem, ["fake-chain"], "inf-uuid-999", "75bcd15")
    infisical_client.build_p12_bundle.return_value = b"fake-p12"
    # Ensure infisical_client does NOT have generate_provisioner_token (Infisical path)
    del infisical_client.generate_provisioner_token

    handler = SlackEnrollmentHandler(
        app=app,
        state_manager=sm,
        ca_client=infisical_client,
        radius_client=radius_client,
        channel_id="C123",
    )

    record = sm.create_request("test-inf-dev", DevicePlatform.WINDOWS, "192.168.1.100")
    token, pin = handler.process_approval(
        request_id=record.request_id,
        approved_name="test-inf-dev",
        vlan=VlanOption.LAN,
    )

    assert len(pin) == 4
    assert token is not None
    infisical_client.generate_key_and_csr.assert_called_once_with("test-inf-dev")
    infisical_client.sign_csr.assert_called_once_with(b"fake-csr")
    infisical_client.build_p12_bundle.assert_called_once()
    radius_client.upsert_user.assert_called_once()
