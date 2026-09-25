from unittest.mock import MagicMock
import pytest

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
    # Verify action buttons exist
    action_block = [b for b in blocks if b.get("type") == "actions"][0]
    action_ids = [elem.get("action_id") for elem in action_block.get("elements", [])]
    assert "quick_approve" in action_ids
    assert "open_edit_modal" in action_ids
    assert "reject_request" in action_ids


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
    radius_client.add_user.assert_called_once_with(
        username="ablack-phone",
        vlan=8,
        description="Auto-enrolled via wifi-enrollment",
    )
    radius_client.reconfigure_service.assert_called_once()

    # Verify state manager was updated
    updated_rec = sm.get_request(record.request_id)
    assert updated_rec.status == EnrollmentStatus.APPROVED
    assert updated_rec.pin == pin
