import logging
import os
import secrets
import threading
import time
from contextlib import asynccontextmanager
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

from services.wifi_enrollment.auth import (
    create_session_token,
    exchange_slack_code,
    generate_slack_oauth_url,
    get_current_admin,
    is_authorized_admin,
    verify_session_token,
)
from services.wifi_enrollment.config import settings
from services.wifi_enrollment.database import CertificateDatabase
from services.wifi_enrollment.models import (
    EnrollmentRequest,
    EnrollmentStatus,
    StatusResponse,
    VlanOption,
    sanitize_device_name,
)
from services.wifi_enrollment.radius_client import FreeRadiusClient
from services.wifi_enrollment.slack_handler import SlackEnrollmentHandler
from services.wifi_enrollment.state_manager import StateManager
from services.wifi_enrollment.step_client import StepCaClient

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("wifi_enrollment")


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
    scope: str = "CERT_ONLY"  # "CERT_ONLY" or "USER_AND_CERT"


def create_app(
    state_manager: Optional[StateManager] = None,
    slack_handler: Optional[SlackEnrollmentHandler] = None,
    step_client: Optional[StepCaClient] = None,
    radius_client: Optional[FreeRadiusClient] = None,
    database: Optional[CertificateDatabase] = None,
) -> FastAPI:
    sm = state_manager or StateManager(
        ttl_seconds=settings.REQUEST_TTL_SECONDS,
        max_pending=settings.MAX_PENDING_REQUESTS,
    )
    db = database or CertificateDatabase(settings.DATABASE_PATH)
    sc = step_client
    rc = radius_client

    rate_limiter = SlidingWindowRateLimiter(
        max_requests=settings.RATE_LIMIT_REQUESTS,
        window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
    )

    static_dir = os.path.join(os.path.dirname(__file__), "static")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
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

    app = FastAPI(
        title="Spoutin Wi-Fi EAP-TLS Enrollment Portal & Admin Dashboard",
        version="0.2.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def add_no_cache_headers(request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        if path.startswith("/api/admin") or path.startswith("/api/status"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

    app.state.state_manager = sm
    app.state.slack_handler = slack_handler
    app.state.step_client = sc
    app.state.radius_client = rc
    app.state.database = db

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
    def get_crl_endpoint():
        """Public endpoint serving the latest Certificate Revocation List (CRL) for FreeRADIUS."""
        client: Optional[StepCaClient] = app.state.step_client
        if not client:
            raise HTTPException(status_code=503, detail="step-ca client is not initialized.")
        try:
            crl_bytes = client.get_crl()
            return Response(content=crl_bytes, media_type="application/x-pkcs7-crl")
        except Exception as e:
            logger.error(f"Failed to fetch CRL from step-ca: {e}", exc_info=True)
            raise HTTPException(status_code=502, detail=f"Failed to retrieve CRL: {e}")

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

        return {
            "request_id": record.request_id,
            "device_name": record.device_name,
            "status": record.status.value,
        }

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
        result = sm.consume_download(download_token)
        if not result:
            raise HTTPException(
                status_code=404,
                detail="Download token is invalid, expired, or has already been used.",
            )

        p12_bytes, filename = result
        return Response(
            content=p12_bytes,
            media_type="application/x-pkcs12",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
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
                    text=f"✅ *Approved* `{target_name}` for *VLAN {vlan.value} ({vlan.label})* by @{admin.get('name', 'Admin')} via Web Dashboard",
                )

            return {
                "status": "approved",
                "device_name": target_name,
                "vlan": vlan.value,
                "pin": pin,
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
        return db.list_certificates(
            status=status,
            search=search,
            vlan_id=vlan_id,
            limit=limit,
            offset=offset,
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

        step: Optional[StepCaClient] = app.state.step_client
        if not step:
            raise HTTPException(status_code=503, detail="step-ca client is not initialized.")

        # 1. Revoke certificate in step-ca (updates CRL)
        try:
            step.revoke_certificate(serial, reason=body.reason)
        except Exception as e:
            logger.error(f"step-ca revocation failed: {e}", exc_info=True)
            raise HTTPException(status_code=502, detail=f"Failed to revoke certificate in step-ca: {e}")

        # 2. Optionally delete/disable FreeRADIUS user in OPNsense
        if body.scope == "USER_AND_CERT":
            radius: Optional[FreeRadiusClient] = app.state.radius_client
            if radius:
                try:
                    radius.delete_user(cert["device_name"])
                except Exception as e:
                    logger.error(f"Failed to delete FreeRADIUS user during revocation: {e}", exc_info=True)

        # 3. Update database record
        db.revoke_certificate(serial, reason=body.reason, scope=body.scope)

        return {
            "status": "revoked",
            "serial": serial,
            "scope": body.scope,
            "reason": body.reason,
        }

    return app


# Default app instance for production uvicorn execution
def init_production_app() -> FastAPI:
    sm = StateManager(
        ttl_seconds=settings.REQUEST_TTL_SECONDS,
        max_pending=settings.MAX_PENDING_REQUESTS,
    )
    db = CertificateDatabase(settings.DATABASE_PATH)
    step_client = StepCaClient(
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
    radius_client = FreeRadiusClient(
        url=settings.OPNSENSE_URL,
        api_key=settings.OPNSENSE_API_KEY,
        api_secret=settings.OPNSENSE_API_SECRET,
        verify_ssl=settings.OPNSENSE_VERIFY_SSL,
    )

    slack_handler = None
    socket_mode_handler = None

    if settings.SLACK_BOT_TOKEN and settings.SLACK_APP_TOKEN:
        logger.info(
            f"Configuring Slack Bot token ({settings.SLACK_BOT_TOKEN[:9]}...) "
            f"and Socket Mode token ({settings.SLACK_APP_TOKEN[:9]}...) for channel {settings.SLACK_CHANNEL_ID}"
        )
        bolt_app = App(token=settings.SLACK_BOT_TOKEN)
        slack_handler = SlackEnrollmentHandler(
            app=bolt_app,
            state_manager=sm,
            step_client=step_client,
            radius_client=radius_client,
            channel_id=settings.SLACK_CHANNEL_ID,
            database=db,
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
        step_client=step_client,
        radius_client=radius_client,
        database=db,
    )
    if socket_mode_handler:
        app.state.socket_mode_handler = socket_mode_handler

    return app


app = init_production_app()
