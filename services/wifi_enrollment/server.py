import logging
import os
import threading
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

from services.wifi_enrollment.config import settings
from services.wifi_enrollment.models import (
    EnrollmentRequest,
    EnrollmentStatus,
    StatusResponse,
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
        # Take the leftmost client IP
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "127.0.0.1"


def create_app(
    state_manager: Optional[StateManager] = None,
    slack_handler: Optional[SlackEnrollmentHandler] = None,
) -> FastAPI:
    sm = state_manager or StateManager(
        ttl_seconds=settings.REQUEST_TTL_SECONDS,
        max_pending=settings.MAX_PENDING_REQUESTS,
    )
    rate_limiter = SlidingWindowRateLimiter(
        max_requests=settings.RATE_LIMIT_REQUESTS,
        window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
    )

    static_dir = os.path.join(os.path.dirname(__file__), "static")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Startup: optionally start Slack Socket Mode handler in background thread
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
        title="Spoutin Wi-Fi EAP-TLS Enrollment Portal",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.state.state_manager = sm
    app.state.slack_handler = slack_handler

    # Mount static assets if directory exists
    if os.path.exists(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/")
    def index():
        index_file = os.path.join(static_dir, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"status": "ok", "service": "wifi-enrollment"}

    @app.post("/api/request")
    def submit_request(req: EnrollmentRequest, request: Request):
        client_ip = get_client_ip(request)

        # 1. Enforce rate limiting
        if not rate_limiter.is_allowed(client_ip):
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded. Please wait 10 minutes before requesting again.",
            )

        # 2. Register request in state manager
        try:
            record = sm.create_request(
                device_name=req.device_name,
                platform=req.platform,
                client_ip=client_ip,
            )
        except ValueError as e:
            raise HTTPException(status_code=429, detail=str(e))

        # 3. Post to Slack if handler configured
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

    return app


# Default app instance for production uvicorn execution
def init_production_app() -> FastAPI:
    sm = StateManager(
        ttl_seconds=settings.REQUEST_TTL_SECONDS,
        max_pending=settings.MAX_PENDING_REQUESTS,
    )
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
        )
        socket_mode_handler = SocketModeHandler(
            app=bolt_app,
            app_token=settings.SLACK_APP_TOKEN,
        )
    else:
        logger.warning(
            "SLACK_BOT_TOKEN and/or SLACK_APP_TOKEN are not set! Slack integration and Socket Mode are DISABLED."
        )

    app = create_app(state_manager=sm, slack_handler=slack_handler)
    if socket_mode_handler:
        app.state.socket_mode_handler = socket_mode_handler

    return app


app = init_production_app()
