from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient

from services.wifi_enrollment.models import DevicePlatform, VlanOption
from services.wifi_enrollment.server import create_app
from services.wifi_enrollment.state_manager import StateManager


@pytest.fixture
def test_app():
    state_manager = StateManager(ttl_seconds=300, max_pending=5)
    slack_handler = MagicMock()
    slack_handler.post_enrollment_card.return_value = ("C123", "123.456")

    app = create_app(state_manager=state_manager, slack_handler=slack_handler)
    client = TestClient(app)
    return client, state_manager, slack_handler


def test_submit_request_success(test_app):
    client, sm, slack = test_app
    resp = client.post(
        "/api/request",
        json={"device_name": "ablack-phone", "platform": "android"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "request_id" in data
    assert data["status"] == "pending"
    assert data["device_name"] == "ablack-phone"

    # Verify slack post was triggered
    slack.post_enrollment_card.assert_called_once()


def test_submit_request_slack_failure(test_app):
    client, sm, slack = test_app
    slack.post_enrollment_card.side_effect = Exception("channel_not_found")

    resp = client.post(
        "/api/request",
        json={"device_name": "device-fail", "platform": "android"},
    )
    assert resp.status_code == 502
    assert "channel_not_found" in resp.json().get("detail", "")

    # Ensure no pending request remains
    assert len(sm._requests) == 1
    rec = list(sm._requests.values())[0]
    assert rec.status.value == "rejected"


def test_submit_request_validation_error(test_app):
    client, _, _ = test_app
    resp = client.post(
        "/api/request",
        json={"device_name": "admin", "platform": "android"},
    )
    assert resp.status_code == 422


def test_rate_limiting(test_app):
    client, sm, _ = test_app
    client.headers = {"X-Forwarded-For": "192.168.1.100"}

    # Limit is 3 requests per IP
    for i in range(3):
        r = client.post("/api/request", json={"device_name": f"device-{i+1}"})
        assert r.status_code == 200

    # 4th request must be rate limited (429)
    r4 = client.post("/api/request", json={"device_name": "device-4"})
    assert r4.status_code == 429
    assert "rate limit" in r4.json().get("detail", "").lower()


def test_polling_status(test_app):
    client, sm, _ = test_app
    resp = client.post(
        "/api/request",
        json={"device_name": "ablack-phone", "platform": "android"},
    )
    req_id = resp.json()["request_id"]

    # Initially pending
    status_resp = client.get(f"/api/status/{req_id}")
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] == "pending"

    # Simulate approval
    dummy_p12 = b"dummy_p12_binary_payload"
    token, pin = sm.approve_request(
        request_id=req_id,
        approved_name="ablack-phone",
        vlan=VlanOption.SEMI_PRIVATE,
        p12_bytes=dummy_p12,
        pin="4829",
    )

    # Next poll must be approved with pin and download token
    status_resp2 = client.get(f"/api/status/{req_id}")
    assert status_resp2.status_code == 200
    data2 = status_resp2.json()
    assert data2["status"] == "approved"
    assert data2["pin"] == "4829"
    assert data2["download_token"] == token
    assert data2["vlan_id"] == 8


def test_download_endpoint(test_app):
    client, sm, _ = test_app
    record = sm.create_request("ablack-phone", DevicePlatform.ANDROID, "127.0.0.1")
    dummy_p12 = b"dummy_p12_binary_payload"
    token, _ = sm.approve_request(
        request_id=record.request_id,
        approved_name="ablack-phone",
        vlan=VlanOption.SEMI_PRIVATE,
        p12_bytes=dummy_p12,
        pin="4829",
    )

    # First download succeeds
    dl_resp = client.get(f"/api/download/{token}")
    assert dl_resp.status_code == 200
    assert dl_resp.content == dummy_p12
    assert "attachment" in dl_resp.headers["Content-Disposition"]
    assert "ablack-phone.p12" in dl_resp.headers["Content-Disposition"]

    # Second download succeeds within 24h approval window (time-based)
    dl_resp2 = client.get(f"/api/download/{token}")
    assert dl_resp2.status_code == 200
    assert dl_resp2.content == dummy_p12

    # Invalid download token returns 404
    bad_resp = client.get("/api/download/nonexistent-token-123")
    assert bad_resp.status_code == 404


def test_index_page(test_app):
    client, _, _ = test_app
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Spoutin Wi-Fi Access" in resp.text
    assert "favicon.svg" in resp.text
    assert "logo.svg" in resp.text

    # Verify static assets serve properly
    favicon_resp = client.get("/static/favicon.svg")
    assert favicon_resp.status_code == 200
    assert "<svg" in favicon_resp.text

    logo_resp = client.get("/static/logo.svg")
    assert logo_resp.status_code == 200
    assert "<svg" in logo_resp.text


def test_status_events_endpoint(test_app):
    client, sm, _ = test_app
    rec = sm.create_request("dev-sse", DevicePlatform.ANDROID, "10.0.0.5")

    resp404 = client.get("/api/status/non-existent-id/events")
    assert resp404.status_code == 404
