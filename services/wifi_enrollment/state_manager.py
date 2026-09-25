import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Optional

from services.wifi_enrollment.models import DevicePlatform, EnrollmentStatus, VlanOption


@dataclass
class RequestRecord:
    request_id: str
    device_name: str
    platform: DevicePlatform
    client_ip: str
    status: EnrollmentStatus
    created_at: float
    expires_at: float
    approved_name: Optional[str] = None
    vlan: Optional[VlanOption] = None
    pin: Optional[str] = None
    download_token: Optional[str] = None
    p12_data: Optional[bytes] = None
    error_message: Optional[str] = None
    slack_message_ts: Optional[str] = None
    slack_channel_id: Optional[str] = None


class StateManager:
    """Thread-safe in-memory state manager for Wi-Fi enrollment requests."""

    def __init__(self, ttl_seconds: int = 900, max_pending: int = 10):
        self.ttl_seconds = ttl_seconds
        self.max_pending = max_pending
        self._lock = threading.RLock()
        self._requests: dict[str, RequestRecord] = {}
        self._token_to_id: dict[str, str] = {}

    def create_request(
        self, device_name: str, platform: DevicePlatform, client_ip: str
    ) -> RequestRecord:
        with self._lock:
            self._prune_expired_locked()
            pending_count = sum(
                1 for r in self._requests.values() if r.status == EnrollmentStatus.PENDING
            )
            if pending_count >= self.max_pending:
                raise ValueError(
                    f"Maximum pending requests limit ({self.max_pending}) reached. "
                    "Please wait for existing requests to be reviewed."
                )

            req_id = str(uuid.uuid4())
            now = time.time()
            record = RequestRecord(
                request_id=req_id,
                device_name=device_name,
                platform=platform,
                client_ip=client_ip,
                status=EnrollmentStatus.PENDING,
                created_at=now,
                expires_at=now + self.ttl_seconds,
            )
            self._requests[req_id] = record
            return record

    def get_request(self, request_id: str) -> Optional[RequestRecord]:
        with self._lock:
            record = self._requests.get(request_id)
            if not record:
                return None

            # Check if expired
            if record.status == EnrollmentStatus.PENDING and time.time() > record.expires_at:
                record.status = EnrollmentStatus.EXPIRED
                record.error_message = "Request expired waiting for administrator approval."

            return record

    def approve_request(
        self,
        request_id: str,
        approved_name: str,
        vlan: VlanOption,
        p12_bytes: bytes,
        pin: Optional[str] = None,
    ) -> tuple[str, str]:
        with self._lock:
            record = self._requests.get(request_id)
            if not record:
                raise KeyError(f"Request {request_id} not found")

            # Generate 4-digit PIN if not provided and high-entropy download token
            final_pin = pin or f"{secrets.randbelow(10000):04d}"
            token = secrets.token_urlsafe(32)

            record.status = EnrollmentStatus.APPROVED
            record.approved_name = approved_name
            record.vlan = vlan
            record.pin = final_pin
            record.download_token = token
            record.p12_data = p12_bytes
            self._token_to_id[token] = request_id

            return token, final_pin

    def reject_request(
        self, request_id: str, reason: str = "Request was rejected by administrator."
    ) -> bool:
        with self._lock:
            record = self._requests.get(request_id)
            if not record:
                return False

            record.status = EnrollmentStatus.REJECTED
            record.error_message = reason
            return True

    def consume_download(self, download_token: str) -> Optional[tuple[bytes, str]]:
        """Single-use download: returns (p12_bytes, filename) and immediately purges from memory."""
        with self._lock:
            req_id = self._token_to_id.pop(download_token, None)
            if not req_id:
                return None

            record = self._requests.get(req_id)
            if not record or not record.p12_data:
                return None

            p12_bytes = record.p12_data
            filename = f"{record.approved_name or record.device_name}.p12"

            # Purge private key data from memory immediately
            record.p12_data = None
            record.download_token = None

            return p12_bytes, filename

    def update_slack_info(
        self, request_id: str, channel_id: str, message_ts: str
    ) -> None:
        with self._lock:
            record = self._requests.get(request_id)
            if record:
                record.slack_channel_id = channel_id
                record.slack_message_ts = message_ts

    def cleanup_expired(self) -> int:
        with self._lock:
            return self._prune_expired_locked()

    def _prune_expired_locked(self) -> int:
        now = time.time()
        to_delete = []
        for req_id, record in self._requests.items():
            if now > record.expires_at:
                to_delete.append(req_id)

        for req_id in to_delete:
            rec = self._requests.pop(req_id, None)
            if rec and rec.download_token:
                self._token_to_id.pop(rec.download_token, None)

        return len(to_delete)
