import json
import logging
import os
import time
from typing import Any, Optional

from slack_bolt import App

from services.wifi_enrollment.models import (
    HOSTNAME_REGEX,
    RESERVED_NAMES,
    DevicePlatform,
    EnrollmentStatus,
    VlanOption,
    sanitize_device_name,
)
from services.wifi_enrollment.database import CertificateDatabase
from services.wifi_enrollment.radius_client import FreeRadiusClient
from services.wifi_enrollment.state_manager import RequestRecord, StateManager
from services.wifi_enrollment.step_client import StepCaClient

logger = logging.getLogger(__name__)


class SlackEnrollmentHandler:
    """Manages Slack Block Kit UI, interactive actions, and modals for Wi-Fi enrollment approvals."""

    def __init__(
        self,
        app: App,
        state_manager: StateManager,
        step_client: StepCaClient,
        radius_client: FreeRadiusClient,
        channel_id: str,
        database: Optional[CertificateDatabase] = None,
        broadcaster: Optional[Any] = None,
    ):
        self.app = app
        self.state_manager = state_manager
        self.step_client = step_client
        self.radius_client = radius_client
        self.channel_id = channel_id
        self.database = database
        self.broadcaster = broadcaster

        self._register_handlers()

    def build_enrollment_blocks(self, record: RequestRecord) -> list[dict]:
        """Constructs interactive Slack message card with Quick Approve, Edit, and Reject."""
        # Check if user already exists in FreeRADIUS or SQLite for warning badge
        exists_radius = self.radius_client.user_exists(record.device_name)
        exists_db = self.database.device_name_exists(record.device_name) if self.database else False
        is_update = exists_radius or exists_db
        status_note = (
            "⚠️ *Existing Device (Re-enrollment / Update)*"
            if is_update
            else "🟢 *New Device*"
        )

        return [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🔔 New Wi-Fi Enrollment Request",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Device Name:*\n`{record.device_name}`"},
                    {"type": "mrkdwn", "text": "*Target VLAN:*\n`8` (SemiPrivate - Default)"},
                    {"type": "mrkdwn", "text": f"*Platform:*\n{record.platform.value.capitalize()}"},
                    {"type": "mrkdwn", "text": f"*Client IP:*\n`{record.client_ip}`"},
                    {"type": "mrkdwn", "text": f"*Status:*\n{status_note}"},
                ],
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "⚡ Quick Approve",
                            "emoji": True,
                        },
                        "style": "primary",
                        "action_id": "quick_approve",
                        "value": record.request_id,
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "✏️ Edit & Approve",
                            "emoji": True,
                        },
                        "action_id": "open_edit_modal",
                        "value": record.request_id,
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "❌ Reject",
                            "emoji": True,
                        },
                        "style": "danger",
                        "action_id": "reject_request",
                        "value": record.request_id,
                    },
                ],
            },
        ]

    def build_edit_modal(self, record: RequestRecord) -> dict:
        """Constructs interactive modal to edit device name and choose dynamic VLAN."""
        vlan_options = [
            VlanOption.SEMI_PRIVATE,
            VlanOption.LAN,
            VlanOption.DMS,
            VlanOption.IOT,
        ]

        select_options = [
            {
                "text": {"type": "plain_text", "text": opt.label},
                "value": str(opt.value),
            }
            for opt in vlan_options
        ]

        initial_vlan = {
            "text": {"type": "plain_text", "text": VlanOption.SEMI_PRIVATE.label},
            "value": str(VlanOption.SEMI_PRIVATE.value),
        }

        return {
            "type": "modal",
            "callback_id": "submit_edit_approval",
            "title": {"type": "plain_text", "text": "Edit & Approve Device"},
            "submit": {"type": "plain_text", "text": "Approve & Generate"},
            "close": {"type": "plain_text", "text": "Cancel"},
            "private_metadata": json.dumps({"request_id": record.request_id}),
            "blocks": [
                {
                    "type": "input",
                    "block_id": "device_name_block",
                    "element": {
                        "type": "plain_text_input",
                        "action_id": "device_name_input",
                        "initial_value": record.device_name,
                        "placeholder": {"type": "plain_text", "text": "e.g. ablack-phone"},
                    },
                    "label": {"type": "plain_text", "text": "Device Name / Wi-Fi Identity"},
                },
                {
                    "type": "input",
                    "block_id": "vlan_block",
                    "element": {
                        "type": "static_select",
                        "action_id": "vlan_select",
                        "placeholder": {"type": "plain_text", "text": "Select VLAN"},
                        "options": select_options,
                        "initial_option": initial_vlan,
                    },
                    "label": {"type": "plain_text", "text": "Dynamic Assigned VLAN"},
                },
                {
                    "type": "input",
                    "block_id": "overwrite_block",
                    "optional": True,
                    "element": {
                        "type": "checkboxes",
                        "action_id": "overwrite_checkbox",
                        "options": [
                            {
                                "text": {
                                    "type": "mrkdwn",
                                    "text": "Allow overwrite if user already exists in FreeRADIUS",
                                },
                                "value": "overwrite",
                            }
                        ],
                    },
                    "label": {"type": "plain_text", "text": "Overwrite Protection"},
                },
            ],
        }

    def validate_modal_submission(
        self, device_name: str, allow_overwrite: bool
    ) -> dict[str, str]:
        """Validates device name syntax and detects duplicates in FreeRADIUS."""
        errors: dict[str, str] = {}
        sanitized = sanitize_device_name(device_name)

        if not sanitized or len(sanitized) < 2 or len(sanitized) > 32:
            errors["device_name_block"] = "Device name must be between 2 and 32 characters."
            return errors

        if not HOSTNAME_REGEX.match(sanitized):
            errors["device_name_block"] = (
                "Device name must contain only lowercase letters, digits, and hyphens."
            )
            return errors

        if sanitized in RESERVED_NAMES:
            errors["device_name_block"] = f"'{sanitized}' is a reserved network name."
            return errors

        exists_radius = self.radius_client.user_exists(sanitized)
        exists_db = self.database.device_name_exists(sanitized) if self.database else False
        if not allow_overwrite and (exists_radius or exists_db):
            errors["device_name_block"] = (
                f"User '{sanitized}' already exists! "
                "Pick a unique name or check 'Allow overwrite' below."
            )
            return errors

        return errors

    def process_approval(
        self,
        request_id: str,
        approved_name: str,
        vlan: VlanOption,
    ) -> tuple[str, str]:
        """Executes full PKI minting, FreeRADIUS user registration, and state transition."""
        logger.info(f"Processing approval for request {request_id}: {approved_name} on VLAN {vlan.value}")

        # 1. Generate key and CSR
        private_key, csr_pem = self.step_client.generate_key_and_csr(approved_name)

        # 2. Get step-ca token
        token = self.step_client.generate_provisioner_token(approved_name)

        # 3. Sign CSR via step-ca REST API
        leaf_pem, chain_pem = self.step_client.sign_csr(csr_pem, token)

        # Read Root & Intermediate CA certificates from configured paths if available
        root_pem = b""
        inter_pem = b""
        if os.path.exists(self.step_client.root_cert_path):
            with open(self.step_client.root_cert_path, "rb") as f:
                root_pem = f.read()
        if os.path.exists(self.step_client.intermediate_cert_path):
            with open(self.step_client.intermediate_cert_path, "rb") as f:
                inter_pem = f.read()
        elif chain_pem:
            inter_pem = chain_pem[0]

        # 4. Generate 4-digit PIN and build .p12 bundle
        record = self.state_manager.get_request(request_id)
        if not record:
            raise KeyError(f"Request {request_id} not found in state manager")

        # 5. Add or update user in FreeRADIUS and reconfigure
        desc = f"Spoutin PKI | req:{request_id} | vlan:{vlan.value}"
        self.radius_client.upsert_user(
            username=approved_name,
            vlan=vlan.value,
            description=desc,
        )
        self.radius_client.reconfigure_service()

        import secrets
        pin = f"{secrets.randbelow(10000):04d}"

        # 6. Record certificate in persistent SQLite database
        try:
            from cryptography import x509
            leaf_cert = x509.load_pem_x509_certificate(leaf_pem)
            serial_str = str(leaf_cert.serial_number)
            if self.database:
                opn_uuid = self.radius_client.get_user_uuid(approved_name)
                now = int(time.time())
                self.database.insert_certificate(
                    serial_number=serial_str,
                    device_name=approved_name,
                    platform=record.platform.value,
                    vlan_id=vlan.value,
                    vlan_label=vlan.label,
                    client_ip=record.client_ip,
                    cert_pem=leaf_pem.decode("utf-8") if isinstance(leaf_pem, bytes) else leaf_pem,
                    issued_at=now,
                    expires_at=now + 52560 * 3600,
                    opnsense_uuid=opn_uuid,
                    request_id=request_id,
                    pin=pin,
                )
        except Exception as e:
            logger.error(f"Failed to record certificate to database: {e}", exc_info=True)

        p12_bytes = self.step_client.build_p12_bundle(
            private_key=private_key,
            cert_pem=leaf_pem,
            intermediate_pem=inter_pem,
            root_pem=root_pem,
            pin=pin,
            friendly_name=approved_name,
        )

        # 6. Mark request as approved in state manager
        download_token, final_pin = self.state_manager.approve_request(
            request_id=request_id,
            approved_name=approved_name,
            vlan=vlan,
            p12_bytes=p12_bytes,
            pin=pin,
        )

        if self.broadcaster:
            self.broadcaster.publish_request(
                request_id=request_id,
                event="approved",
                data={
                    "status": "approved",
                    "request_id": request_id,
                    "device_name": approved_name,
                    "vlan_id": vlan.value,
                    "vlan_label": vlan.label,
                    "download_token": download_token,
                    "pin": final_pin,
                    "radius_identity": approved_name,
                },
            )
            self.broadcaster.publish_admin(
                event="request_approved",
                data={"request_id": request_id, "device_name": approved_name, "vlan_id": vlan.value},
            )

        return download_token, final_pin

    def post_enrollment_card(self, record: RequestRecord) -> tuple[str, str]:
        """Posts interactive card to designated Slack channel."""
        blocks = self.build_enrollment_blocks(record)
        resp = self.app.client.chat_postMessage(
            channel=self.channel_id,
            text=f"New Wi-Fi Enrollment Request: {record.device_name}",
            blocks=blocks,
        )
        channel = resp.get("channel", self.channel_id)
        ts = resp.get("ts", "")
        self.state_manager.update_slack_info(record.request_id, channel, ts)
        return channel, ts

    def _register_handlers(self) -> None:
        """Registers Bolt action listeners."""

        @self.app.action("quick_approve")
        def handle_quick_approve(ack, body):
            ack()
            request_id = body["actions"][0]["value"]
            user_name = body.get("user", {}).get("username", "Admin")
            logger.info(f"Received 'quick_approve' button click from @{user_name} for request {request_id}")
            record = self.state_manager.get_request(request_id)
            if not record or record.status != EnrollmentStatus.PENDING:
                logger.warning(f"Request {request_id} is no longer pending (status: {record.status if record else 'not found'})")
                return

            # Immediate interim acknowledgment to eliminate perceived delay
            self._update_channel_message(
                channel=body["channel"]["id"],
                ts=body["message"]["ts"],
                text=f"⏳ *Processing approval* for `{record.device_name}` by @{user_name}... Please wait.",
            )

            try:
                download_token, pin = self.process_approval(
                    request_id=request_id,
                    approved_name=record.device_name,
                    vlan=VlanOption.SEMI_PRIVATE,
                )
                self._update_channel_message(
                    channel=body["channel"]["id"],
                    ts=body["message"]["ts"],
                    text=f"✅ *Approved* `{record.device_name}` for *VLAN 8 (SemiPrivate)* by @{user_name} (Import PIN: `{pin}`)",
                )
            except Exception as e:
                logger.error(f"Error during quick approve: {e}", exc_info=True)
                self.state_manager.reject_request(
                    request_id,
                    reason="An internal error occurred while generating your Wi-Fi credentials. Please contact your network administrator.",
                )
                self._update_channel_error(
                    channel=body["channel"]["id"],
                    ts=body["message"]["ts"],
                    record=record,
                    error_msg=str(e),
                    user_name=user_name,
                    vlan=VlanOption.SEMI_PRIVATE,
                )

        @self.app.action("open_edit_modal")
        def handle_open_modal(ack, body):
            ack()
            request_id = body["actions"][0]["value"]
            user_name = body.get("user", {}).get("username", "Admin")
            logger.info(f"Received 'open_edit_modal' button click from @{user_name} for request {request_id}")
            record = self.state_manager.get_request(request_id)
            if not record or record.status != EnrollmentStatus.PENDING:
                logger.warning(f"Request {request_id} is no longer pending (status: {record.status if record else 'not found'})")
                return

            modal = self.build_edit_modal(record)
            self.app.client.views_open(
                trigger_id=body["trigger_id"],
                view=modal,
            )

        @self.app.view("submit_edit_approval")
        def handle_modal_submission(ack, body, view):
            metadata = json.loads(view.get("private_metadata", "{}"))
            request_id = metadata.get("request_id")
            values = view.get("state", {}).get("values", {})
            user_name = body.get("user", {}).get("username", "Admin")

            device_name = values["device_name_block"]["device_name_input"]["value"]
            vlan_str = values["vlan_block"]["vlan_select"]["selected_option"]["value"]
            vlan = VlanOption(int(vlan_str))

            overwrite_opts = values.get("overwrite_block", {}).get("overwrite_checkbox", {}).get("selected_options", [])
            allow_overwrite = any(opt.get("value") == "overwrite" for opt in overwrite_opts)

            logger.info(f"Received modal submission for {request_id} from @{user_name}: device='{device_name}', vlan={vlan.value}, overwrite={allow_overwrite}")

            # Validate input and duplicates
            errors = self.validate_modal_submission(device_name, allow_overwrite)
            if errors:
                logger.warning(f"Validation failed for modal submission: {errors}")
                ack(response_action="errors", errors=errors)
                return

            # Acknowledge modal closure
            ack()

            # Process approval
            sanitized_name = sanitize_device_name(device_name)
            record = self.state_manager.get_request(request_id)
            if record and record.status == EnrollmentStatus.PENDING:
                # Immediate interim acknowledgment in channel
                if record.slack_channel_id and record.slack_message_ts:
                    self._update_channel_message(
                        channel=record.slack_channel_id,
                        ts=record.slack_message_ts,
                        text=f"⏳ *Processing approval* for `{sanitized_name}` (VLAN {vlan.value}) by @{user_name}... Please wait.",
                    )
                try:
                    download_token, pin = self.process_approval(request_id, sanitized_name, vlan)
                    if record.slack_channel_id and record.slack_message_ts:
                        self._update_channel_message(
                            channel=record.slack_channel_id,
                            ts=record.slack_message_ts,
                            text=f"✅ *Approved* `{sanitized_name}` for *VLAN {vlan.value} ({vlan.label})* by @{user_name} (Import PIN: `{pin}`)",
                        )
                except Exception as e:
                    logger.error(f"Error during modal approval: {e}", exc_info=True)
                    self.state_manager.reject_request(
                        request_id,
                        reason="An internal error occurred while generating your Wi-Fi credentials. Please contact your network administrator.",
                    )
                    if record.slack_channel_id and record.slack_message_ts:
                        self._update_channel_error(
                            channel=record.slack_channel_id,
                            ts=record.slack_message_ts,
                            record=record,
                            error_msg=str(e),
                            user_name=user_name,
                            vlan=vlan,
                        )

        @self.app.action("reject_request")
        def handle_reject(ack, body):
            ack()
            request_id = body["actions"][0]["value"]
            user_name = body.get("user", {}).get("username", "Admin")
            logger.info(f"Received 'reject_request' button click from @{user_name} for request {request_id}")
            record = self.state_manager.get_request(request_id)
            if not record or record.status != EnrollmentStatus.PENDING:
                return

            self.state_manager.reject_request(request_id)
            if self.broadcaster:
                self.broadcaster.publish_request(
                    request_id=request_id,
                    event="rejected",
                    data={"status": "rejected", "request_id": request_id, "message": "Request was rejected by administrator."},
                )
                self.broadcaster.publish_admin(
                    event="request_rejected",
                    data={"request_id": request_id, "device_name": record.device_name},
                )
            self._update_channel_message(
                channel=body["channel"]["id"],
                ts=body["message"]["ts"],
                text=f"❌ *Rejected* `{record.device_name}` by @{user_name}",
            )

    def _update_channel_message(self, channel: str, ts: str, text: str) -> None:
        try:
            self.app.client.chat_update(
                channel=channel,
                ts=ts,
                text=text,
                blocks=[
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": text},
                    }
                ],
            )
        except Exception as e:
            logger.error(f"Failed to update Slack channel message: {e}")

    def _update_channel_error(
        self,
        channel: str,
        ts: str,
        record: RequestRecord,
        error_msg: str,
        user_name: str,
        vlan: VlanOption,
    ) -> None:
        """Updates Slack message with a structured technical error card when approval fails."""
        time_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "❌ Wi-Fi Enrollment Failed",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Device Name:*\n`{record.approved_name or record.device_name}`"},
                    {"type": "mrkdwn", "text": f"*Attempted By:*\n@{user_name}"},
                    {"type": "mrkdwn", "text": f"*Target VLAN:*\n`{vlan.value}` ({vlan.label})"},
                    {"type": "mrkdwn", "text": f"*Timestamp:*\n{time_str}"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Actual Technical Error:*\n```{error_msg}```",
                },
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "ℹ️ *Client Webpage:* Updated with a generic error message and polling was stopped.",
                    }
                ],
            },
        ]
        try:
            self.app.client.chat_update(
                channel=channel,
                ts=ts,
                text=f"❌ Approval failed for {record.device_name}: {error_msg}",
                blocks=blocks,
            )
        except Exception as e:
            logger.error(f"Failed to update Slack channel with error card: {e}")
