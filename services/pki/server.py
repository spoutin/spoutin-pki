import asyncio
import base64
import hashlib
import logging
import os
import secrets
import threading
import time
from contextlib import asynccontextmanager
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

from starlette.types import ASGIApp, Receive, Scope, Send

from services.pki.broadcaster import EventBroadcaster

from services.pki.auth import (
    create_session_token,
    exchange_slack_code,
    generate_slack_oauth_url,
    get_current_admin,
    is_authorized_admin,
    verify_session_token,
)
from services.pki.config import settings
from services.pki.database import CertificateDatabase
from services.pki.models import (
    EnrollmentRequest,
    EnrollmentStatus,
    StatusResponse,
    VlanOption,
    sanitize_device_name,
)
from services.pki.infisical_client import InfisicalCaClient
from services.pki.openbao_client import OpenBaoCaClient
from services.pki.radius_client import FreeRadiusClient
from services.pki.slack_handler import SlackEnrollmentHandler
from services.pki.state_manager import StateManager
from services.pki.step_client import StepCaClient

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("pki")


class SlidingWindowRateLimiter:
    """Thread-safe sliding window rate limiter per IP address."""

    def __init__(self, max_requests: int = 3, window_seconds: int = 600):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._ip_timestamps: dict[str, list[float]] = {}

    def is_allowed(self, ip: str) -> bool:
        with self._lock:
            now = time.time()
            timestamps = self._ip_timestamps.setdefault(ip, [])
            # Prune older than window
            timestamps = [t for t in timestamps if now - t < self.window_seconds]
            self._ip_timestamps[ip] = timestamps

            if len(timestamps) >= self.max_requests:
                return False

            timestamps.append(now)
            return True


def get_client_ip(request: Request) -> str:
    """Extracts client IP, respecting X-Forwarded-For if reverse proxied by Caddy."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "127.0.0.1"


# --- Request Bodies for Admin API ---
class ApproveRequestBody(BaseModel):
    approved_name: Optional[str] = None
    vlan_id: Optional[int] = 8


class RejectRequestBody(BaseModel):
    reason: Optional[str] = "Rejected by administrator from web dashboard."


class RevokeRequestBody(BaseModel):
    reason: str = "cessationOfOperation"
    scope: str = "USER_AND_CERT"  # "CERT_ONLY" or "USER_AND_CERT"


class UpdateVlanRequestBody(BaseModel):
    vlan_id: int


class SshEnrollmentRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    username: str = Field(..., min_length=1, max_length=50)
    device_name: str = Field(..., min_length=1, max_length=100)
    public_key: str = Field(..., min_length=20)
    principals: Optional[list[str]] = None
    ttl: Optional[str] = "70080h"
    key_filename: Optional[str] = "id_ed25519"


class SshQuickSignRequest(BaseModel):
    key_id: str = Field(..., min_length=1, max_length=50)
    public_key: str = Field(..., min_length=20)
    principals: list[str] = Field(default_factory=lambda: ["ablack", "root", "operator"])
    ttl: str = "70080h"
    role: str = "admin-user"
    key_filename: Optional[str] = "id_ed25519"


class SshApproveRequest(BaseModel):
    key_id: Optional[str] = None
    device_name: Optional[str] = None
    principals: Optional[list[str]] = None
    ttl: Optional[str] = "70080h"
    role: Optional[str] = None
    key_filename: Optional[str] = None


def calculate_ssh_fingerprint(public_key: str) -> str:
    parts = public_key.strip().split()
    if len(parts) >= 2:
        try:
            raw_bytes = base64.b64decode(parts[1])
            fp = base64.b64encode(hashlib.sha256(raw_bytes).digest()).decode("ascii").rstrip("=")
            return f"SHA256:{fp}"
        except Exception:
            pass
    return f"SHA256:{hashlib.sha256(public_key.strip().encode()).hexdigest()[:32]}"


REVOCATION_REASON_LABELS = {
    "cessationOfOperation": "Decommissioned / Retired",
    "keyCompromise": "Key Compromise",
    "affiliationChanged": "Device Lost or Stolen",
    "superseded": "Superseded by New Cert",
    "privilegeWithdrawn": "Access Withdrawn",
    "unspecified": "Revoked (Unspecified)",
    "certificateHold": "Certificate Hold",
    "cACompromise": "CA Compromise",
}


def sync_radius_vlans(
    db: CertificateDatabase,
    rc: Optional[FreeRadiusClient],
    bc: Optional[EventBroadcaster],
) -> int:
    """Syncs VLAN assignments from FreeRADIUS into the local database."""
    if not rc:
        return 0
    try:
        users = rc.list_users()
        if not users:
            return 0

        updated_count = 0
        for username, data in users.items():
            vlan_id = data.get("vlan")
            if vlan_id is None:
                continue
            try:
                vlan_opt = VlanOption(vlan_id)
                label = vlan_opt.label
            except ValueError:
                label = f"VLAN {vlan_id}"

            changed = db.update_vlan_by_device_name(username, vlan_id, label)
            if changed > 0:
                updated_count += changed

        if updated_count > 0 and bc:
            bc.publish_admin("vlan_synced", {"updated": updated_count})

        return updated_count
    except Exception as e:
        logger.error(f"Error during FreeRADIUS VLAN sync: {e}", exc_info=True)
        return 0


def create_app(
    state_manager: Optional[StateManager] = None,
    slack_handler: Optional[SlackEnrollmentHandler] = None,
    step_client: Optional[Any] = None,
    radius_client: Optional[FreeRadiusClient] = None,
    database: Optional[CertificateDatabase] = None,
    broadcaster: Optional[EventBroadcaster] = None,
    ca_client: Optional[Any] = None,
) -> FastAPI:
    sm = state_manager or StateManager(
        ttl_seconds=settings.REQUEST_TTL_SECONDS,
        max_pending=settings.MAX_PENDING_REQUESTS,
    )
    db = database or CertificateDatabase(settings.DATABASE_PATH)
    sc = ca_client or step_client
    rc = radius_client
    bc = broadcaster or EventBroadcaster()

    rate_limiter = SlidingWindowRateLimiter(
        max_requests=settings.RATE_LIMIT_REQUESTS,
        window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
    )

    static_dir = os.path.join(os.path.dirname(__file__), "static")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        bc.set_loop(asyncio.get_running_loop())

        # Background FreeRADIUS periodic sync loop (every 60s)
        async def run_radius_sync():
            while True:
                await asyncio.sleep(60)
                try:
                    sync_radius_vlans(db, rc, bc)
                except Exception as e:
                    logger.debug(f"Background FreeRADIUS sync error: {e}")

        sync_task = asyncio.create_task(run_radius_sync())

        socket_handler = getattr(app.state, "socket_mode_handler", None)
        if socket_handler:
            def run_socket_mode():
                try:
                    logger.info("Connecting to Slack Socket Mode WebSocket...")
                    socket_handler.start()
                except Exception as e:
                    logger.error(f"FATAL: Slack Socket Mode connection failed or crashed: {e}", exc_info=True)

            t = threading.Thread(target=run_socket_mode, name="slack-socket-mode", daemon=True)
            t.start()
            logger.info("Slack Socket Mode listener thread initialized.")
        else:
            logger.warning("No socket_mode_handler registered on app.state! Slack interactive events will not be received.")
        yield
        sync_task.cancel()

    app = FastAPI(
        title="Spoutin PKI Certificate Portal & Admin Dashboard",
        version="0.3.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    class NoCacheASGIMiddleware:
        def __init__(self, asgi_app: ASGIApp):
            self.app = asgi_app

        async def __call__(self, scope: Scope, receive: Receive, send: Send):
            if scope["type"] != "http":
                return await self.app(scope, receive, send)

            path = scope.get("path", "")
            if (path.startswith("/api/admin") or path.startswith("/api/status")) and not path.endswith("/events"):
                async def send_wrapper(message):
                    if message["type"] == "http.response.start":
                        headers = list(message.get("headers", []))
                        headers.append((b"cache-control", b"no-store, no-cache, must-revalidate, max-age=0"))
                        headers.append((b"pragma", b"no-cache"))
                        headers.append((b"expires", b"0"))
                        message["headers"] = headers
                    await send(message)
                return await self.app(scope, receive, send_wrapper)

            return await self.app(scope, receive, send)

    app.add_middleware(NoCacheASGIMiddleware)

    app.state.state_manager = sm
    app.state.slack_handler = slack_handler
    app.state.ca_client = sc
    app.state.step_client = sc
    app.state.radius_client = rc
    app.state.database = db
    app.state.broadcaster = bc

    # Mount static assets if directory exists
    if os.path.exists(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    # Dependency for Admin Protection
    def require_admin(request: Request) -> dict:
        secret = getattr(app.state, "session_secret_key", settings.SESSION_SECRET_KEY)
        allowed = getattr(app.state, "allowed_admin_emails", settings.ADMIN_SLACK_EMAILS)
        return get_current_admin(request, secret_key=secret, allowed_emails=allowed)

    # ================= PUBLIC ROUTES =================

    @app.get("/")
    def index():
        index_file = os.path.join(static_dir, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"status": "ok", "service": "wifi-enrollment"}

    @app.get("/crl")
    @app.get("/crl.pem")
    def get_crl_endpoint(request: Request):
        """Public endpoint serving the latest Certificate Revocation List (CRL) for FreeRADIUS."""
        client = app.state.ca_client or app.state.step_client
        if not client:
            raise HTTPException(status_code=503, detail="CA client is not initialized.")
        try:
            is_pem = request.url.path.endswith(".pem")
            crl_bytes = client.get_crl(as_pem=is_pem)

            # Generate ETag based on SHA-256 of the CRL payload
            etag = f'"{hashlib.sha256(crl_bytes).hexdigest()}"'
            if_none_match = request.headers.get("if-none-match")

            # Check for conditional GET
            if if_none_match and if_none_match.strip() == etag:
                return Response(
                    status_code=304,
                    headers={
                        "ETag": etag,
                        "Cache-Control": "public, no-cache",
                    },
                )

            media_type = "application/x-pem-file" if is_pem else "application/x-pkcs7-crl"
            headers = {
                "ETag": etag,
                "Cache-Control": "public, no-cache",
            }
            return Response(content=crl_bytes, media_type=media_type, headers=headers)
        except Exception as e:
            logger.error(f"Failed to fetch CRL from CA: {e}", exc_info=True)
            raise HTTPException(status_code=502, detail=f"Failed to retrieve CRL: {e}")

    @app.get("/ssh-ca.pub", response_class=PlainTextResponse)
    def get_ssh_ca_public_key_endpoint():
        """Public endpoint serving the OpenSSH CA public key."""
        client = app.state.ca_client or getattr(app.state, "step_client", None)
        if not client or not hasattr(client, "get_ssh_ca_public_key"):
            raise HTTPException(status_code=503, detail="OpenBao SSH CA is not configured or unavailable")
        try:
            ca_pub = client.get_ssh_ca_public_key()
            return PlainTextResponse(content=ca_pub + "\n", media_type="text/plain")
        except Exception as e:
            logger.error(f"Failed to fetch SSH CA public key: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail="Failed to retrieve SSH CA public key")

    @app.post("/api/ssh/request")
    def submit_ssh_request(body: SshEnrollmentRequest):
        principals = body.principals or ([body.username, "root", "operator"] if body.username == "ablack" else [body.username, "operator"])
        fp = calculate_ssh_fingerprint(body.public_key)
        req_id = db.create_ssh_request(
            name=body.name,
            username=body.username,
            device_name=body.device_name,
            public_key=body.public_key,
            key_fingerprint=fp,
            principals=principals,
            ttl=body.ttl or "70080h",
            key_filename=body.key_filename or "id_ed25519",
        )
        sh = getattr(app.state, "slack_handler", None)
        if sh and hasattr(sh, "send_ssh_request_notification"):
            try:
                sh.send_ssh_request_notification(
                    request_id=req_id,
                    name=body.name,
                    username=body.username,
                    device_name=body.device_name,
                    fingerprint=fp,
                    principals=principals,
                )
            except Exception as e:
                logger.warning(f"Failed to send Slack notification for SSH request {req_id}: {e}")

        return {"request_id": req_id, "status": "PENDING"}

    @app.get("/api/ssh/status/{request_id}")
    def get_ssh_request_status(request_id: str):
        req = db.get_ssh_request(request_id)
        if not req:
            raise HTTPException(status_code=404, detail="SSH request not found")
        return req

    @app.post("/api/request")
    def submit_request(req: EnrollmentRequest, request: Request):
        client_ip = get_client_ip(request)

        if not rate_limiter.is_allowed(client_ip):
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded. Please wait 10 minutes before requesting again.",
            )

        try:
            record = sm.create_request(
                device_name=req.device_name,
                platform=req.platform,
                client_ip=client_ip,
            )
        except ValueError as e:
            raise HTTPException(status_code=429, detail=str(e))

        handler: Optional[SlackEnrollmentHandler] = app.state.slack_handler
        if handler:
            try:
                handler.post_enrollment_card(record)
            except Exception as e:
                logger.error(f"Failed to post Slack notification: {e}", exc_info=True)
                sm.reject_request(record.request_id, reason=f"Failed to notify administrator via Slack: {e}")
                raise HTTPException(
                    status_code=502,
                    detail=f"Failed to notify administrator via Slack: {e}. Please contact your network administrator.",
                )

        # Notify admin dashboard subscribers via SSE
        bc.publish_admin(
            event="request_created",
            data={
                "request_id": record.request_id,
                "device_name": record.device_name,
                "platform": record.platform.value,
                "client_ip": record.client_ip,
            },
        )

        return {
            "request_id": record.request_id,
            "device_name": record.device_name,
            "status": record.status.value,
        }

    @app.get("/api/status/{request_id}/events")
    async def stream_request_status_events(request_id: str):
        record = sm.get_request(request_id)
        if not record:
            raise HTTPException(status_code=404, detail="Request not found or expired")

        return StreamingResponse(
            bc.subscribe_request(request_id),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-transform",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    @app.get("/api/status/{request_id}", response_model=StatusResponse)
    def check_status(request_id: str):
        record = sm.get_request(request_id)
        if not record:
            raise HTTPException(status_code=404, detail="Request not found or expired")

        approved_name = record.approved_name or record.device_name
        vlan_label = record.vlan.label if record.vlan else None
        vlan_val = record.vlan.value if record.vlan else None

        return StatusResponse(
            request_id=record.request_id,
            status=record.status,
            device_name=record.device_name,
            vlan_id=vlan_val,
            vlan_label=vlan_label,
            download_token=record.download_token,
            pin=record.pin,
            radius_identity=approved_name,
            radius_domain=settings.RADIUS_SERVER_DOMAIN,
            platform=record.platform,
            message=record.error_message,
        )

    @app.get("/api/download/{download_token}")
    def download_bundle(download_token: str):
        result = sm.get_download(download_token)
        if not result:
            raise HTTPException(
                status_code=404,
                detail="Download token is invalid or the 24-hour download window has expired.",
            )

        p12_bytes, filename = result
        return Response(
            content=p12_bytes,
            media_type="application/x-pkcs12",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Cache-Control": "no-store, no-cache, must-revalidate",
            },
        )

    # ================= SLACK OAUTH & ADMIN AUTH ROUTES =================

    @app.get("/admin/login")
    def admin_login_page():
        login_file = os.path.join(static_dir, "admin_login.html")
        if os.path.exists(login_file):
            return FileResponse(login_file)
        return {"status": "ok", "message": "Admin login page (admin_login.html)"}

    @app.get("/admin/auth/login")
    def slack_oauth_login(request: Request):
        if not settings.SLACK_CLIENT_ID:
            raise HTTPException(status_code=500, detail="SLACK_CLIENT_ID is not configured in environment.")

        state = secrets.token_urlsafe(16)
        redirect_uri = f"https://{request.headers.get('host', 'wifi.' + settings.NETWORK_DOMAIN)}/admin/auth/callback"
        oauth_url = generate_slack_oauth_url(settings.SLACK_CLIENT_ID, redirect_uri, state)

        response = RedirectResponse(oauth_url, status_code=302)
        response.set_cookie(
            key="slack_oauth_state",
            value=state,
            max_age=300,
            httponly=True,
            samesite="lax",
        )
        return response

    @app.get("/admin/auth/callback")
    def slack_oauth_callback(code: str, state: str, request: Request):
        cookie_state = request.cookies.get("slack_oauth_state")
        if not cookie_state or cookie_state != state:
            raise HTTPException(status_code=400, detail="Invalid OAuth state parameter.")

        redirect_uri = f"https://{request.headers.get('host', 'wifi.' + settings.NETWORK_DOMAIN)}/admin/auth/callback"
        try:
            user_info = exchange_slack_code(
                client_id=settings.SLACK_CLIENT_ID,
                client_secret=settings.SLACK_CLIENT_SECRET,
                code=code,
                redirect_uri=redirect_uri,
            )
        except Exception as e:
            logger.error(f"Slack OAuth exchange failed: {e}", exc_info=True)
            raise HTTPException(status_code=401, detail=f"Slack authentication failed: {e}")

        email = user_info.get("email", "")
        allowed = getattr(app.state, "allowed_admin_emails", settings.ADMIN_SLACK_EMAILS)
        if not is_authorized_admin(email, allowed_list=allowed):
            raise HTTPException(
                status_code=403,
                detail=f"Access denied: '{email}' is not in the authorized administrators list.",
            )

        secret = getattr(app.state, "session_secret_key", settings.SESSION_SECRET_KEY)
        session_token = create_session_token(
            email=email,
            name=user_info.get("name", "Admin"),
            picture=user_info.get("picture", ""),
            secret_key=secret,
        )

        resp = RedirectResponse("/admin", status_code=302)
        resp.set_cookie(
            key="wifi_admin_session",
            value=session_token,
            max_age=86400,
            httponly=True,
            samesite="lax",
        )
        resp.delete_cookie("slack_oauth_state")
        return resp

    @app.post("/admin/auth/logout")
    def admin_logout():
        resp = RedirectResponse("/admin/login", status_code=302)
        resp.delete_cookie("wifi_admin_session")
        return resp

    # ================= ADMIN DASHBOARD & REST APIS =================

    @app.get("/admin")
    def admin_dashboard_page(request: Request):
        cookie_token = request.cookies.get("wifi_admin_session")
        secret = getattr(app.state, "session_secret_key", settings.SESSION_SECRET_KEY)
        allowed = getattr(app.state, "allowed_admin_emails", settings.ADMIN_SLACK_EMAILS)

        # If not authenticated, redirect to login page
        payload = verify_session_token(cookie_token, secret_key=secret) if cookie_token else None
        if not payload or not is_authorized_admin(payload.get("email", ""), allowed_list=allowed):
            return RedirectResponse("/admin/login", status_code=302)

        dashboard_file = os.path.join(static_dir, "admin.html")
        if os.path.exists(dashboard_file):
            return FileResponse(dashboard_file)
        return {"status": "ok", "message": "Admin dashboard page (admin.html)"}

    @app.get("/api/admin/me")
    def get_admin_profile(admin: dict = Depends(require_admin)):
        return {
            "email": admin.get("email"),
            "name": admin.get("name"),
            "picture": admin.get("picture"),
        }

    @app.get("/api/admin/events")
    async def stream_admin_events(admin: dict = Depends(require_admin)):
        return StreamingResponse(
            bc.subscribe_admin(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-transform",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    @app.get("/api/admin/stats")
    def get_dashboard_stats(admin: dict = Depends(require_admin)):
        return db.get_stats()

    @app.get("/api/admin/requests")
    def get_pending_requests(admin: dict = Depends(require_admin)):
        with sm._lock:
            pending = [
                {
                    "request_id": r.request_id,
                    "device_name": r.device_name,
                    "platform": r.platform.value,
                    "client_ip": r.client_ip,
                    "created_at": r.created_at,
                    "expires_at": r.expires_at,
                    "is_update": bool(db.device_name_exists(r.device_name)),
                }
                for r in sm._requests.values()
                if r.status == EnrollmentStatus.PENDING and time.time() <= r.expires_at
            ]
        return pending

    @app.post("/api/admin/requests/{request_id}/approve")
    def web_approve_request(
        request_id: str,
        body: ApproveRequestBody,
        admin: dict = Depends(require_admin),
    ):
        record = sm.get_request(request_id)
        if not record or record.status != EnrollmentStatus.PENDING:
            raise HTTPException(status_code=404, detail="Request not found or no longer pending.")

        handler: Optional[SlackEnrollmentHandler] = app.state.slack_handler
        if not handler:
            raise HTTPException(status_code=503, detail="Enrollment handler is not initialized.")

        target_name = sanitize_device_name(body.approved_name or record.device_name)
        vlan = VlanOption(body.vlan_id) if body.vlan_id else VlanOption.SEMI_PRIVATE

        try:
            download_token, pin = handler.process_approval(
                request_id=request_id,
                approved_name=target_name,
                vlan=vlan,
            )

            # Update Slack channel card in-place if message was posted
            if record.slack_channel_id and record.slack_message_ts:
                handler._update_channel_message(
                    channel=record.slack_channel_id,
                    ts=record.slack_message_ts,
                    text=f"✅ *Approved* `{target_name}` for *VLAN {vlan.value} ({vlan.label})* by @{admin.get('name', 'Admin')} via Web Dashboard (Import PIN: `{pin}`)",
                )

            return {
                "status": "approved",
                "device_name": target_name,
                "vlan": vlan.value,
                "pin": pin,
                "serial_number": record.serial_number,
            }
        except Exception as e:
            logger.error(f"Error during web dashboard approval: {e}", exc_info=True)
            sm.reject_request(request_id, reason="An internal error occurred during certificate generation.")
            if record.slack_channel_id and record.slack_message_ts:
                handler._update_channel_error(
                    channel=record.slack_channel_id,
                    ts=record.slack_message_ts,
                    record=record,
                    error_msg=str(e),
                    user_name=admin.get("name", "Admin"),
                    vlan=vlan,
                )
            raise HTTPException(status_code=500, detail=f"Approval failed: {e}")

    @app.post("/api/admin/requests/{request_id}/reject")
    def web_reject_request(
        request_id: str,
        body: RejectRequestBody,
        admin: dict = Depends(require_admin),
    ):
        record = sm.get_request(request_id)
        if not record or record.status != EnrollmentStatus.PENDING:
            raise HTTPException(status_code=404, detail="Request not found or no longer pending.")

        sm.reject_request(request_id, reason=body.reason or "Rejected by administrator from web dashboard.")

        # Notify waiting client & admin stream
        bc.publish_request(
            request_id=request_id,
            event="rejected",
            data={"status": "rejected", "request_id": request_id, "message": body.reason or "Request was rejected by administrator."},
        )
        bc.publish_admin(
            event="request_rejected",
            data={"request_id": request_id, "device_name": record.device_name},
        )

        handler: Optional[SlackEnrollmentHandler] = app.state.slack_handler
        if handler and record.slack_channel_id and record.slack_message_ts:
            handler._update_channel_message(
                channel=record.slack_channel_id,
                ts=record.slack_message_ts,
                text=f"❌ *Rejected* `{record.device_name}` by @{admin.get('name', 'Admin')} via Web Dashboard",
            )

        return {"status": "rejected", "request_id": request_id}

    @app.get("/api/admin/certificates")
    def list_certificates(
        status: Optional[str] = Query(None),
        search: Optional[str] = Query(None),
        vlan_id: Optional[int] = Query(None),
        limit: int = Query(100, ge=1, le=500),
        offset: int = Query(0, ge=0),
        admin: dict = Depends(require_admin),
    ):
        certs = db.list_certificates(
            status=status,
            search=search,
            vlan_id=vlan_id,
            limit=limit,
            offset=offset,
        )
        for c in certs:
            reason = c.get("revocation_reason")
            c["revocation_reason_label"] = REVOCATION_REASON_LABELS.get(reason, reason) if reason else None
            serial = c.get("serial_number")
            if serial:
                try:
                    c["serial_hex"] = format(int(serial), "X")
                except ValueError:
                    c["serial_hex"] = str(serial).upper()
            else:
                c["serial_hex"] = None
            c["download_available"] = bool(
                c.get("status") != "REVOKED"
                and serial
                and sm.has_download_by_serial(serial)
            )
        return certs

    @app.get("/api/admin/certificates/{serial}/download")
    def admin_download_certificate(
        serial: str,
        admin: dict = Depends(require_admin),
    ):
        cert = db.get_certificate(serial)
        if not cert:
            raise HTTPException(status_code=404, detail="Certificate not found in database.")

        if cert.get("status") == "REVOKED":
            raise HTTPException(status_code=400, detail="Certificate has been revoked.")

        result = sm.get_download_by_serial(serial)
        if not result:
            raise HTTPException(
                status_code=404,
                detail="Certificate bundle not found or 24-hour download window has expired.",
            )

        p12_bytes, filename = result
        return Response(
            content=p12_bytes,
            media_type="application/x-pkcs12",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Cache-Control": "no-store, no-cache, must-revalidate",
            },
        )

    @app.post("/api/admin/certificates/{serial}/revoke")
    def revoke_certificate_endpoint(
        serial: str,
        body: RevokeRequestBody,
        admin: dict = Depends(require_admin),
    ):
        cert = db.get_certificate(serial)
        if not cert:
            raise HTTPException(status_code=404, detail="Certificate not found in database.")

        if cert.get("status") == "REVOKED":
            raise HTTPException(status_code=400, detail="Certificate is already revoked.")

        ca = app.state.ca_client or app.state.step_client
        if not ca:
            raise HTTPException(status_code=503, detail="CA client is not initialized.")

        # 1. Revoke certificate in CA (updates CRL)
        target_id_or_serial = cert.get("certificate_id") or serial
        try:
            ca.revoke_certificate(target_id_or_serial, reason=body.reason, cert_pem=cert.get("cert_pem"))
        except TypeError:
            ca.revoke_certificate(target_id_or_serial, reason=body.reason)
        except Exception as e:
            logger.error(f"CA revocation failed: {e}", exc_info=True)
            raise HTTPException(status_code=502, detail=f"Failed to revoke certificate in CA: {e}")

        radius: Optional[FreeRadiusClient] = app.state.radius_client

        # 2. Push updated CRL directly to OPNsense and restart FreeRADIUS daemon
        if radius:
            try:
                crl_pem = ca.get_crl(as_pem=True)
                if crl_pem:
                    radius.push_crl(crl_pem)
                    radius.restart_service()
            except Exception as e:
                logger.error(f"Failed to push updated CRL to OPNsense during revocation: {e}", exc_info=True)

        # 3. Optionally delete/disable FreeRADIUS user in OPNsense
        if body.scope == "USER_AND_CERT":
            if radius:
                try:
                    radius.delete_user(cert["device_name"])
                except Exception as e:
                    logger.error(f"Failed to delete FreeRADIUS user during revocation: {e}", exc_info=True)

        # 4. Update database record
        db.revoke_certificate(serial, reason=body.reason, scope=body.scope)

        # 5. Immediately purge in-memory ephemeral .p12
        sm.revoke_download(serial)

        # Notify admin dashboard via SSE
        bc.publish_admin(
            event="cert_revoked",
            data={"serial_number": serial, "reason": body.reason, "scope": body.scope},
        )

        return {
            "status": "revoked",
            "serial": serial,
            "scope": body.scope,
            "reason": body.reason,
        }

    @app.post("/api/admin/certificates/{serial}/vlan")
    def update_certificate_vlan_endpoint(
        serial: str,
        body: UpdateVlanRequestBody,
        admin: dict = Depends(require_admin),
    ):
        cert = db.get_certificate(serial)
        if not cert:
            raise HTTPException(status_code=404, detail="Certificate not found in database.")

        if cert.get("status") == "REVOKED":
            raise HTTPException(status_code=400, detail="Cannot change VLAN for a revoked certificate.")

        try:
            vlan_opt = VlanOption(body.vlan_id)
            vlan_label = vlan_opt.label
        except ValueError:
            vlan_label = f"VLAN {body.vlan_id}"

        # 1. Update FreeRADIUS if client is available
        rc_client: Optional[FreeRadiusClient] = app.state.radius_client
        if rc_client:
            try:
                req_id = cert.get("request_id")
                desc = (
                    f"Spoutin PKI | vlan:{body.vlan_id} | req:{req_id}"
                    if req_id
                    else f"Spoutin PKI | vlan:{body.vlan_id}"
                )
                rc_client.update_user_vlan(cert["device_name"], body.vlan_id, description=desc)
            except Exception as e:
                logger.error(f"Failed to update FreeRADIUS VLAN for {cert['device_name']}: {e}", exc_info=True)
                raise HTTPException(status_code=502, detail=f"Failed to update FreeRADIUS: {e}")

        # 2. Update Database
        db.update_certificate_vlan(serial, body.vlan_id, vlan_label)

        # 3. Notify Admin Dashboards via SSE
        bc.publish_admin(
            event="cert_vlan_updated",
            data={
                "serial_number": serial,
                "device_name": cert["device_name"],
                "vlan_id": body.vlan_id,
                "vlan_label": vlan_label,
            },
        )

        return {
            "status": "updated",
            "serial_number": serial,
            "device_name": cert["device_name"],
            "vlan_id": body.vlan_id,
            "vlan_label": vlan_label,
        }

    @app.post("/api/admin/sync-radius")
    def sync_radius_endpoint(admin: dict = Depends(require_admin)):
        rc_client: Optional[FreeRadiusClient] = app.state.radius_client
        count = sync_radius_vlans(db, rc_client, bc)
        return {"status": "synced", "updated": count}

    # ================= ADMIN SSH ROUTES =================

    @app.post("/api/admin/ssh/quick-sign")
    def admin_ssh_quick_sign(body: SshQuickSignRequest, admin: dict = Depends(require_admin)):
        client = app.state.ca_client or getattr(app.state, "step_client", None)
        if not client or not hasattr(client, "sign_ssh_public_key"):
            raise HTTPException(status_code=503, detail="OpenBao SSH CA is not configured")
        fp = calculate_ssh_fingerprint(body.public_key)
        try:
            res = client.sign_ssh_public_key(
                public_key=body.public_key,
                key_id=body.key_id,
                principals=body.principals,
                ttl=body.ttl,
                role=body.role,
            )
            serial = str(res.get("serial_number", ""))
            cert = res.get("signed_key", "")
            now = int(time.time())
            valid_to = now + 8 * 365 * 86400
            db.save_ssh_certificate(
                serial_number=serial,
                key_id=body.key_id,
                principals=body.principals,
                public_key=body.public_key,
                key_fingerprint=fp,
                certificate=cert,
                valid_from=now,
                valid_to=valid_to,
                key_filename=body.key_filename or "id_ed25519",
            )
            return {
                "serial_number": serial,
                "certificate": cert,
                "key_id": body.key_id,
                "principals": body.principals,
                "valid_to": valid_to,
                "key_filename": body.key_filename or "id_ed25519",
            }
        except Exception as e:
            logger.error(f"Quick-sign SSH key failed: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=f"OpenBao SSH signing error: {e}")

    @app.get("/api/admin/ssh/requests")
    def list_admin_ssh_requests(status: Optional[str] = None, admin: dict = Depends(require_admin)):
        return db.list_ssh_requests(status=status)

    @app.post("/api/admin/ssh/requests/{request_id}/approve")
    def approve_admin_ssh_request(request_id: str, body: SshApproveRequest, admin: dict = Depends(require_admin)):
        req = db.get_ssh_request(request_id)
        if not req:
            raise HTTPException(status_code=404, detail="SSH request not found")
        client = app.state.ca_client or getattr(app.state, "step_client", None)
        if not client or not hasattr(client, "sign_ssh_public_key"):
            raise HTTPException(status_code=503, detail="OpenBao SSH CA is not configured")

        effective_key_id = (body.key_id or req["username"]).strip()
        effective_device_name = (body.device_name or req.get("device_name", "")).strip()
        effective_key_filename = (body.key_filename or req.get("key_filename") or "id_ed25519").strip()
        principals = body.principals or [p.strip() for p in req["principals"].split(",") if p.strip()]
        ttl = body.ttl or req.get("requested_ttl") or "70080h"
        role = body.role or ("admin-user" if any(p in ("root", "ablack") for p in principals) else "operator-user")

        try:
            res = client.sign_ssh_public_key(
                public_key=req["public_key"],
                key_id=effective_key_id,
                principals=principals,
                ttl=ttl,
                role=role,
            )
            serial = str(res.get("serial_number", ""))
            cert = res.get("signed_key", "")
            now = int(time.time())
            valid_to = now + 8 * 365 * 86400
            db.save_ssh_certificate(
                serial_number=serial,
                key_id=effective_key_id,
                principals=principals,
                public_key=req["public_key"],
                key_fingerprint=req["key_fingerprint"],
                certificate=cert,
                valid_from=now,
                valid_to=valid_to,
                key_filename=effective_key_filename,
            )
            db.update_ssh_request_status(request_id, "APPROVED", reviewed_by=admin.get("email", "admin"))
            return {
                "serial_number": serial,
                "certificate": cert,
                "key_id": effective_key_id,
                "principals": principals,
                "valid_to": valid_to,
                "key_filename": effective_key_filename,
            }
        except Exception as e:
            logger.error(f"Approval of SSH request {request_id} failed: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=f"OpenBao SSH signing error: {e}")

    @app.post("/api/admin/ssh/requests/{request_id}/reject")
    def reject_admin_ssh_request(request_id: str, admin: dict = Depends(require_admin)):
        success = db.update_ssh_request_status(request_id, "REJECTED", reviewed_by=admin.get("email", "admin"))
        if not success:
            raise HTTPException(status_code=404, detail="SSH request not found")
        return {"status": "ok", "request_id": request_id}

    @app.get("/api/admin/ssh/certificates")
    def list_admin_ssh_certificates(status: Optional[str] = None, admin: dict = Depends(require_admin)):
        return db.list_ssh_certificates(status=status)

    @app.post("/api/admin/ssh/certificates/{serial}/revoke")
    def revoke_admin_ssh_certificate(serial: str, admin: dict = Depends(require_admin)):
        success = db.revoke_ssh_certificate(serial)
        if not success:
            raise HTTPException(status_code=404, detail="SSH certificate not found")
        return {"status": "ok", "serial_number": serial}

    return app


def create_ca_client():
    provider = getattr(settings, "CA_PROVIDER", "openbao").lower()
    if provider == "openbao":
        logger.info(
            f"Initializing OpenBao PKI client (URL: {settings.OPENBAO_URL}, Mount: {settings.OPENBAO_PKI_MOUNT}, Role: {settings.OPENBAO_ROLE})"
        )
        return OpenBaoCaClient(
            base_url=settings.OPENBAO_URL,
            role_id=settings.OPENBAO_ROLE_ID,
            secret_id=settings.OPENBAO_SECRET_ID,
            token=settings.OPENBAO_TOKEN,
            pki_mount=settings.OPENBAO_PKI_MOUNT,
            role_name=settings.OPENBAO_ROLE,
            domain=settings.NETWORK_DOMAIN,
            default_ttl=settings.CERT_VALIDITY_HOURS,
            verify_ssl=settings.OPENBAO_VERIFY_SSL,
        )
    elif provider == "infisical":
        logger.info(
            f"Initializing Infisical PKI client (URL: {settings.INFISICAL_URL}, CA ID: {settings.INFISICAL_CA_ID})"
        )
        return InfisicalCaClient(
            base_url=settings.INFISICAL_URL,
            client_id=settings.INFISICAL_CLIENT_ID,
            client_secret=settings.INFISICAL_CLIENT_SECRET,
            project_id=settings.INFISICAL_PROJECT_ID,
            ca_id=settings.INFISICAL_CA_ID,
            domain=settings.NETWORK_DOMAIN,
            default_ttl=settings.CERT_VALIDITY_HOURS,
            verify_ssl=settings.INFISICAL_VERIFY_SSL,
        )
    else:
        logger.info(f"Initializing step-ca client (URL: {settings.STEP_CA_URL})")
        return StepCaClient(
            ca_url=settings.STEP_CA_URL,
            domain=settings.NETWORK_DOMAIN,
            provisioner_name=settings.STEP_CA_PROVISIONER_NAME,
            ca_config_path=settings.STEP_CA_CONFIG_PATH,
            password_file=settings.STEP_CA_PASSWORD_FILE,
            provisioner_key_path=settings.STEP_CA_PROVISIONER_KEY_PATH,
            provisioner_password=settings.STEP_CA_PROVISIONER_PASSWORD,
            root_cert_path=settings.STEP_ROOT_CERT_PATH,
            intermediate_cert_path=settings.STEP_INTERMEDIATE_CERT_PATH,
            verify_ssl=False,
        )


# Default app instance for production uvicorn execution
def init_production_app() -> FastAPI:
    sm = StateManager(
        ttl_seconds=settings.REQUEST_TTL_SECONDS,
        max_pending=settings.MAX_PENDING_REQUESTS,
    )
    db = CertificateDatabase(settings.DATABASE_PATH)
    ca_client = create_ca_client()
    radius_client = FreeRadiusClient(
        url=settings.OPNSENSE_URL,
        api_key=settings.OPNSENSE_API_KEY,
        api_secret=settings.OPNSENSE_API_SECRET,
        verify_ssl=settings.OPNSENSE_VERIFY_SSL,
        intermediate_ca_refid=settings.OPNSENSE_INTERMEDIATE_CA_REFID,
    )

    slack_handler = None
    socket_mode_handler = None
    broadcaster = EventBroadcaster()

    if settings.SLACK_BOT_TOKEN and settings.SLACK_APP_TOKEN:
        logger.info(
            f"Configuring Slack Bot token ({settings.SLACK_BOT_TOKEN[:9]}...) "
            f"and Socket Mode token ({settings.SLACK_APP_TOKEN[:9]}...) for channel {settings.SLACK_CHANNEL_ID}"
        )
        # Temporarily mask SLACK_CLIENT_ID and SLACK_CLIENT_SECRET from os.environ
        # while instantiating Bolt App. Otherwise Bolt auto-detects them and attempts
        # to configure multi-team distributed OAuth with an InstallationStore, ignoring
        # SLACK_BOT_TOKEN and breaking single-team Socket Mode button authorization.
        env_cid = os.environ.pop("SLACK_CLIENT_ID", None)
        env_csec = os.environ.pop("SLACK_CLIENT_SECRET", None)
        try:
            bolt_app = App(token=settings.SLACK_BOT_TOKEN)
        finally:
            if env_cid is not None:
                os.environ["SLACK_CLIENT_ID"] = env_cid
            if env_csec is not None:
                os.environ["SLACK_CLIENT_SECRET"] = env_csec
        slack_handler = SlackEnrollmentHandler(
            app=bolt_app,
            state_manager=sm,
            ca_client=ca_client,
            radius_client=radius_client,
            channel_id=settings.SLACK_CHANNEL_ID,
            database=db,
            broadcaster=broadcaster,
        )
        socket_mode_handler = SocketModeHandler(
            app=bolt_app,
            app_token=settings.SLACK_APP_TOKEN,
        )
    else:
        logger.warning(
            "SLACK_BOT_TOKEN and/or SLACK_APP_TOKEN are not set! Slack integration and Socket Mode are DISABLED."
        )

    app = create_app(
        state_manager=sm,
        slack_handler=slack_handler,
        ca_client=ca_client,
        radius_client=radius_client,
        database=db,
        broadcaster=broadcaster,
    )
    if socket_mode_handler:
        app.state.socket_mode_handler = socket_mode_handler

    return app
    if socket_mode_handler:
        app.state.socket_mode_handler = socket_mode_handler

    return app


app = init_production_app()
