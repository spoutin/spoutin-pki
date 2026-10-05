import asyncio
import json
import pytest

from services.pki.broadcaster import EventBroadcaster


@pytest.mark.asyncio
async def test_broadcaster_admin_subscribe_and_publish():
    broadcaster = EventBroadcaster()
    broadcaster.set_loop(asyncio.get_running_loop())

    gen = broadcaster.subscribe_admin()
    first = await anext(gen)
    assert "event: connected" in first

    broadcaster.publish_admin("request_created", {"request_id": "req-1", "device_name": "test-phone"})
    msg = await anext(gen)
    assert "event: request_created" in msg
    assert '"request_id": "req-1"' in msg

    await gen.aclose()


@pytest.mark.asyncio
async def test_broadcaster_request_subscribe_and_publish():
    broadcaster = EventBroadcaster()
    broadcaster.set_loop(asyncio.get_running_loop())

    gen = broadcaster.subscribe_request("req-abc")
    first = await anext(gen)
    assert "event: connected" in first
    assert '"request_id": "req-abc"' in first

    # Publish to a different request - should not be received
    broadcaster.publish_request("req-other", "approved", {"pin": "1234"})

    # Publish to target request
    broadcaster.publish_request("req-abc", "approved", {"pin": "9999", "status": "approved"})
    msg = await anext(gen)
    assert "event: approved" in msg
    assert '"pin": "9999"' in msg

    await gen.aclose()
