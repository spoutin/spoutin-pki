from unittest.mock import MagicMock, patch
import pytest

from services.wifi_enrollment.radius_client import FreeRadiusClient


@patch("requests.Session.post")
def test_user_exists_found(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "rows": [
            {"username": "other-user", "vlan": "1"},
            {"username": "ablack-phone", "vlan": "8"},
        ]
    }
    mock_post.return_value = mock_resp

    client = FreeRadiusClient("https://opnsense.local", "key", "secret")
    assert client.user_exists("ablack-phone") is True
    assert client.user_exists("unknown-device") is False


@patch("requests.Session.post")
def test_add_user_success(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"result": "saved"}
    mock_post.return_value = mock_resp

    client = FreeRadiusClient("https://opnsense.local", "key", "secret")
    result = client.add_user(username="ablack-phone", vlan=8)
    assert result.get("result") == "saved"

    # Verify payload format sent to OPNsense
    call_args = mock_post.call_args
    assert call_args is not None
    payload = call_args.kwargs["json"]["user"]
    assert payload["username"] == "ablack-phone"
    assert payload["vlan"] == "8"
    assert payload["enabled"] == "1"


@patch("requests.Session.post")
def test_add_user_failure(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"result": "failed", "validations": {"user.username": "already exists"}}
    mock_post.return_value = mock_resp

    client = FreeRadiusClient("https://opnsense.local", "key", "secret")
    with pytest.raises(RuntimeError) as exc:
        client.add_user(username="ablack-phone", vlan=8)
    assert "Failed to add FreeRADIUS user" in str(exc.value)


@patch("requests.Session.post")
def test_reconfigure_service_success(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "ok"}
    mock_post.return_value = mock_resp

    client = FreeRadiusClient("https://opnsense.local", "key", "secret")
    assert client.reconfigure_service() is True


@patch("requests.Session.post")
def test_get_user_uuid(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "rows": [
            {"username": "ablack-phone", "uuid": "uuid-1234-abcd"},
        ]
    }
    mock_post.return_value = mock_resp

    client = FreeRadiusClient("https://opnsense.local", "key", "secret")
    assert client.get_user_uuid("ablack-phone") == "uuid-1234-abcd"
    assert client.get_user_uuid("missing") is None


@patch("requests.Session.post")
def test_delete_user_success(mock_post):
    search_resp = MagicMock()
    search_resp.status_code = 200
    search_resp.json.return_value = {
        "rows": [{"username": "ablack-phone", "uuid": "uuid-1234-abcd"}]
    }

    del_resp = MagicMock()
    del_resp.status_code = 200
    del_resp.json.return_value = {"result": "deleted"}

    reconfig_resp = MagicMock()
    reconfig_resp.status_code = 200
    reconfig_resp.json.return_value = {"status": "ok"}

    mock_post.side_effect = [search_resp, del_resp, reconfig_resp]

    client = FreeRadiusClient("https://opnsense.local", "key", "secret")
    assert client.delete_user("ablack-phone") is True

