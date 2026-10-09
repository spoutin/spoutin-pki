import json
import logging
import os
import time
from typing import Any, Optional

from slack_bolt import App

from services.pki.models import (
    HOSTNAME_REGEX,
    RESERVED_NAMES,
    DevicePlatform,
    EnrollmentStatus,
    VlanOption,
    sanitize_device_name,
)
from services.pki.database import CertificateDatabase
from services.pki.radius_client import FreeRadiusClient
from services.pki.state_manager import RequestRecord, StateManager
from services.pki.step_client import StepCaClient

logger = logging.getLogger(__name__)


class SlackEnrollmentHandler:
    """Manages Slack Block Kit UI, interactive actions, and modals for Wi-Fi enrollment approvals."""

    def __init__(
        self,
        app: App,
        state_manager: StateManager,
        ca_client: Any = None,
        radius_client: Optional[FreeRadiusClient] = None,
        channel_id: str = "",
        database: Optional[CertificateDatabase] = None,
        broadcaster: Optional[Any] = None,
        step_client: Any = None,
    ):
        self.app = app
        self.state_manager = state_manager
        self.ca_client = ca_client or step_client
        self.step_client = self.ca_client
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
                        "placeholder": {"type": "plain_text", "text": "e.g. personal-phone"},
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
        private_key, csr_pem = self.ca_client.generate_key_and_csr(approved_name)

        cert_id = None
        leaf_bytes = b""
        if hasattr(self.ca_client, "generate_provisioner_token"):
            # Step-ca flow
            token = self.ca_client.generate_provisioner_token(approved_name)
            leaf_pem, chain_pem = self.ca_client.sign_csr(csr_pem, token)
            root_pem = b""
            inter_pem = b""
            if hasattr(self.ca_client, "root_cert_path") and os.path.exists(self.ca_client.root_cert_path):
                with open(self.ca_client.root_cert_path, "rb") as f:
                    root_pem = f.read()
            if hasattr(self.ca_client, "intermediate_cert_path") and os.path.exists(self.ca_client.intermediate_cert_path):
                with open(self.ca_client.intermediate_cert_path, "rb") as f:
                    inter_pem = f.read()
            elif chain_pem:
                inter_pem = chain_pem[0] if isinstance(chain_pem[0], bytes) else chain_pem[0].encode("utf-8")
            leaf_bytes = leaf_pem.encode("utf-8") if isinstance(leaf_pem, str) else leaf_pem
            build_p12 = lambda p: self.ca_client.build_p12_bundle(
                private_key=private_key,
                cert_pem=leaf_bytes,
                intermediate_pem=inter_pem,
                root_pem=root_pem,
                pin=p,
                friendly_name=approved_name,
            )
        else:
            # Infisical flow
            leaf_pem, chain_pem, cert_id, serial_ret = self.ca_client.sign_csr(csr_pem)
            leaf_bytes = leaf_pem.encode("utf-8") if isinstance(leaf_pem, str) else leaf_pem
            build_p12 = lambda p: self.ca_client.build_p12_bundle(
                private_key=private_key,
                cert_pem=leaf_bytes,
                chain_pems=chain_pem,
                pin=p,
                friendly_name=approved_name,
            )

        # 4. Generate 4-digit PIN and build .p12 bundle
        record = self.state_manager.get_request(request_id)
        if not record:
            raise KeyError(f"Request {request_id} not found in state manager")

        # 5. Add or update user in FreeRADIUS and reconfigure
        desc = f"Spoutin PKI | vlan:{vlan.value} | req:{request_id}"
        self.radius_client.upsert_user(
            username=approved_name,
            vlan=vlan.value,
            description=desc,
        )
        self.radius_client.reconfigure_service()

        import secrets
        pin = f"{secrets.randbelow(10000):04d}"

        # 6. Record certificate in persistent SQLite database
        serial_str: Optional[str] = None
        try:
            from cryptography import x509
            leaf_cert = x509.load_pem_x509_certificate(leaf_bytes)
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
                    cert_pem=leaf_bytes.decode("utf-8") if isinstance(leaf_bytes, bytes) else leaf_bytes,
                    issued_at=now,
                    expires_at=now + 52560 * 3600,
                    opnsense_uuid=opn_uuid,
                    request_id=request_id,
                    pin=pin,
                    certificate_id=cert_id,
                )
        except Exception as e:
            logger.error(f"Failed to record certificate to database: {e}", exc_info=True)

        p12_bytes = build_p12(pin)

        # 6. Mark request as approved in state manager
        download_token, final_pin = self.state_manager.approve_request(
            request_id=request_id,
            approved_name=approved_name,
            vlan=vlan,
            p12_bytes=p12_bytes,
            pin=pin,
            serial_number=serial_str,
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

    def send_ssh_request_notification(
        self,
        request_id: str,
        name: str,
        username: str,
        device_name: str,
        fingerprint: str,
        principals: list[str],
    ) -> str:
        """Posts interactive SSH signing request card to designated Slack channel."""
        principals_str = ", ".join(principals)
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🔑 New SSH Key Signing Request",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Name:*\n{name}"},
                    {"type": "mrkdwn", "text": f"*Device:*\n`{device_name}`"},
                    {"type": "mrkdwn", "text": f"*Key ID:*\n`{username}`"},
                    {"type": "mrkdwn", "text": f"*Principals:*\n`{principals_str}`"},
                    {"type": "mrkdwn", "text": f"*Fingerprint:*\n`{fingerprint}`"},
                ],
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "⚡ Approve SSH",
                            "emoji": True,
                        },
                        "style": "primary",
                        "action_id": "ssh_quick_approve",
                        "value": request_id,
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "✏️ Edit & Approve",
                            "emoji": True,
                        },
                        "action_id": "ssh_open_edit_modal",
                        "value": request_id,
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "❌ Reject",
                            "emoji": True,
                        },
                        "style": "danger",
                        "action_id": "ssh_reject",
                        "value": request_id,
                    },
                ],
            },
        ]
        resp = self.app.client.chat_postMessage(
            channel=self.channel_id,
            text=f"New SSH Key Signing Request: {username} ({device_name})",
            blocks=blocks,
        )
        return resp.get("ts", "")

    def send_ssh_krl_failure_alert(
        self,
        error_detail: str,
        context: str = "",
    ) -> Optional[str]:
        """Posts an operational alert to Slack when OpenSSH KRL generation fails."""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🚨 OpenSSH KRL Generation Failed",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Context:*\n{context or 'Routine generation'}"},
                    {"type": "mrkdwn", "text": "*Impact:*\nServers cannot sync updated revocation list"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Error:*\n```{error_detail}```",
                },
            },
        ]
        try:
            resp = self.app.client.chat_postMessage(
                channel=self.channel_id,
                text=f"🚨 [Spoutin PKI Alert] OpenSSH KRL Generation Failed: {error_detail}",
                blocks=blocks,
            )
            return resp.get("ts", "")
        except Exception as e:
            logger.error(f"Failed to post KRL failure alert to Slack: {e}")
            return None

    def send_ssh_revocation_notification(
        self,
        serial_number: str,
        revoked_by: str,
        reason: str = "",
    ) -> Optional[str]:
        """Posts notification to Slack when an SSH certificate is revoked."""
        fields = [
            {"type": "mrkdwn", "text": f"*Serial Number:*\n`{serial_number}`"},
            {"type": "mrkdwn", "text": f"*Revoked By:*\n{revoked_by}"},
        ]
        if reason:
            fields.append({"type": "mrkdwn", "text": f"*Reason:*\n{reason}"})

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🚫 SSH Certificate Revoked",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": fields,
            },
        ]
        try:
            resp = self.app.client.chat_postMessage(
                channel=self.channel_id,
                text=f"🚫 [Spoutin PKI] SSH Certificate Revoked (Serial: {serial_number})",
                blocks=blocks,
            )
            return resp.get("ts", "")
        except Exception as e:
            logger.error(f"Failed to post SSH revocation to Slack: {e}")
            return None

    def build_ssh_edit_modal(self, req: dict) -> dict:
        """Constructs interactive Slack modal to edit Key ID, principals, device name, and TTL prior to approval."""
        return {
            "type": "modal",
            "callback_id": "submit_ssh_edit_approval",
            "private_metadata": json.dumps({
                "request_id": req["request_id"],
                "slack_channel": req.get("slack_channel_id", self.channel_id),
                "slack_ts": req.get("slack_message_ts", ""),
            }),
            "title": {"type": "plain_text", "text": "Approve SSH Key"},
            "submit": {"type": "plain_text", "text": "Sign & Approve"},
            "close": {"type": "plain_text", "text": "Cancel"},
            "blocks": [
                {
                    "type": "input",
                    "block_id": "key_id_block",
                    "element": {
                        "type": "plain_text_input",
                        "action_id": "key_id_input",
                        "initial_value": req.get("username", ""),
                    },
                    "label": {"type": "plain_text", "text": "Key ID / Username"},
                    "hint": {"type": "plain_text", "text": "Identity stamped into certificate and logged by sshd."},
                },
                {
                    "type": "input",
                    "block_id": "device_name_block",
                    "element": {
                        "type": "plain_text_input",
                        "action_id": "device_name_input",
                        "initial_value": req.get("device_name", ""),
                    },
                    "label": {"type": "plain_text", "text": "Device / Description"},
                },
                {
                    "type": "input",
                    "block_id": "principals_block",
                    "element": {
                        "type": "plain_text_input",
                        "action_id": "principals_input",
                        "initial_value": req.get("principals", "ablack,root,operator"),
                    },
                    "label": {"type": "plain_text", "text": "Authorized Principals (comma-separated)"},
                    "hint": {"type": "plain_text", "text": "Allowed Unix accounts on destination servers."},
                },
                {
                    "type": "input",
                    "block_id": "key_filename_block",
                    "element": {
                        "type": "plain_text_input",
                        "action_id": "key_filename_input",
                        "initial_value": req.get("key_filename", "id_ed25519"),
                    },
                    "label": {"type": "plain_text", "text": "Local Key Filename"},
                    "hint": {"type": "plain_text", "text": "Base name of private key (e.g. id_ed25519 or id_rsa)."},
                },
                {
                    "type": "input",
                    "block_id": "ttl_block",
                    "element": {
                        "type": "plain_text_input",
                        "action_id": "ttl_input",
                        "initial_value": req.get("requested_ttl", "70080h"),
                    },
                    "label": {"type": "plain_text", "text": "Validity (TTL)"},
                },
            ],
        }

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

        @self.app.action("ssh_quick_approve")
        def handle_ssh_quick_approve(ack, body):
            ack()
            request_id = body["actions"][0]["value"]
            user_name = body.get("user", {}).get("username", "Admin")
            logger.info(f"Received 'ssh_quick_approve' click from @{user_name} for request {request_id}")
            if not self.database:
                return
            req = self.database.get_ssh_request(request_id)
            if not req or req.get("status") != "PENDING":
                logger.warning(f"SSH request {request_id} is no longer pending")
                return

            self._update_channel_message(
                channel=body["channel"]["id"],
                ts=body["message"]["ts"],
                text=f"⏳ *Processing SSH key approval* for `{req['username']}` by @{user_name}...",
            )

            try:
                principals = [p.strip() for p in req["principals"].split(",") if p.strip()]
                ttl = req.get("requested_ttl") or "70080h"
                role = "admin-user" if "root" in principals else "operator-user"
                res = self.ca_client.sign_ssh_public_key(
                    public_key=req["public_key"],
                    key_id=req["username"],
                    principals=principals,
                    ttl=ttl,
                    role=role,
                )
                serial = str(res.get("serial_number", ""))
                cert = res.get("signed_key", "")
                now = int(time.time())
                valid_to = now + 8 * 365 * 86400
                self.database.save_ssh_certificate(
                    serial_number=serial,
                    key_id=req["username"],
                    principals=principals,
                    public_key=req["public_key"],
                    key_fingerprint=req["key_fingerprint"],
                    certificate=cert,
                    valid_from=now,
                    valid_to=valid_to,
                )
                self.database.update_ssh_request_status(
                    request_id,
                    "APPROVED",
                    reviewed_by=f"slack:@{user_name}",
                    certificate=cert,
                    serial_number=serial,
                )
                self._update_channel_message(
                    channel=body["channel"]["id"],
                    ts=body["message"]["ts"],
                    text=f"✅ *SSH Key Approved* for `{req['username']}` (`{req['device_name']}`) by @{user_name}.\n*Serial:* `{serial}` | *Principals:* `{','.join(principals)}`",
                )
            except Exception as e:
                logger.error(f"Failed to sign SSH key for request {request_id}: {e}", exc_info=True)
                self._update_channel_message(
                    channel=body["channel"]["id"],
                    ts=body["message"]["ts"],
                    text=f"❌ *Failed to sign SSH key* for `{req['username']}`: {e}",
                )

        @self.app.action("ssh_open_edit_modal")
        def handle_ssh_open_modal(ack, body):
            ack()
            request_id = body["actions"][0]["value"]
            if not self.database:
                return
            req = self.database.get_ssh_request(request_id)
            if not req or req.get("status") != "PENDING":
                return
            req["slack_channel_id"] = body["channel"]["id"]
            req["slack_message_ts"] = body["message"]["ts"]
            modal = self.build_ssh_edit_modal(req)
            self.app.client.views_open(
                trigger_id=body["trigger_id"],
                view=modal,
            )

        @self.app.view("submit_ssh_edit_approval")
        def handle_ssh_modal_submission(ack, body, view):
            ack()
            metadata = json.loads(view.get("private_metadata", "{}"))
            request_id = metadata.get("request_id")
            channel_id = metadata.get("slack_channel")
            ts = metadata.get("slack_ts")
            values = view.get("state", {}).get("values", {})
            user_name = body.get("user", {}).get("username", "Admin")

            key_id = values["key_id_block"]["key_id_input"]["value"].strip()
            device_name = values["device_name_block"]["device_name_input"]["value"].strip()
            principals_raw = values["principals_block"]["principals_input"]["value"]
            principals = [p.strip() for p in principals_raw.split(",") if p.strip()]
            key_filename = values.get("key_filename_block", {}).get("key_filename_input", {}).get("value", "id_ed25519").strip() or "id_ed25519"
            ttl = values["ttl_block"]["ttl_input"]["value"].strip() or "70080h"

            if not self.database:
                return
            req = self.database.get_ssh_request(request_id)
            if not req or req.get("status") != "PENDING":
                return

            if channel_id and ts:
                self._update_channel_message(
                    channel=channel_id,
                    ts=ts,
                    text=f"⏳ *Processing SSH key approval* for `{key_id}` by @{user_name}...",
                )

            try:
                role = "admin-user" if any(p in ("root", "ablack") for p in principals) else "operator-user"
                res = self.ca_client.sign_ssh_public_key(
                    public_key=req["public_key"],
                    key_id=key_id,
                    principals=principals,
                    ttl=ttl,
                    role=role,
                )
                serial = str(res.get("serial_number", ""))
                cert = res.get("signed_key", "")
                now = int(time.time())
                valid_to = now + 8 * 365 * 86400
                self.database.save_ssh_certificate(
                    serial_number=serial,
                    key_id=key_id,
                    principals=principals,
                    public_key=req["public_key"],
                    key_fingerprint=req["key_fingerprint"],
                    certificate=cert,
                    valid_from=now,
                    valid_to=valid_to,
                    key_filename=key_filename,
                )
                self.database.update_ssh_request_status(
                    request_id,
                    "APPROVED",
                    reviewed_by=f"slack:@{user_name}",
                    certificate=cert,
                    serial_number=serial,
                )
                if channel_id and ts:
                    self._update_channel_message(
                        channel=channel_id,
                        ts=ts,
                        text=f"✅ *SSH Key Approved (Customized)* for `{key_id}` (`{device_name}`) by @{user_name}.\n*Serial:* `{serial}` | *Principals:* `{','.join(principals)}` | *TTL:* `{ttl}`",
                    )
            except Exception as e:
                logger.error(f"Failed to sign SSH key for request {request_id}: {e}", exc_info=True)
                if channel_id and ts:
                    self._update_channel_message(
                        channel=channel_id,
                        ts=ts,
                        text=f"❌ *Failed to sign SSH key* for `{key_id}`: {e}",
                    )

        @self.app.action("ssh_reject")
        def handle_ssh_reject(ack, body):
            ack()
            request_id = body["actions"][0]["value"]
            user_name = body.get("user", {}).get("username", "Admin")
            if not self.database:
                return
            req = self.database.get_ssh_request(request_id)
            self.database.update_ssh_request_status(request_id, "REJECTED", reviewed_by=f"slack:@{user_name}")
            username = req["username"] if req else request_id
            self._update_channel_message(
                channel=body["channel"]["id"],
                ts=body["message"]["ts"],
                text=f"❌ *SSH Key Request Rejected* for `{username}` by @{user_name}.",
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
