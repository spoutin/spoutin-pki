from unittest.mock import MagicMock, patch
import pytest
from services.pki.unifi_client import UnifiControllerClient


def test_unifi_client_get_active_clients():
    client = UnifiControllerClient(
        url="https://10.0.0.1",
        api_key="my-key",
        site="default",
    )

    with patch.object(client.session, "get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "meta": {"rc": "ok"},
            "data": [
                {
                    "mac": "00:11:22:33:44:55",
                    "ip": "192.168.1.150",
                    "hostname": "Alice-iPhone",
                    "is_guest": True,
                    "ap_mac": "aa:bb:cc:dd:ee:ff",
                    "rssi": -55,
                }
            ]
        }
        mock_get.return_value = mock_resp

        clients = client.get_active_clients()
        assert "00:11:22:33:44:55" in clients
        assert clients["00:11:22:33:44:55"]["ip"] == "192.168.1.150"
        assert clients["00:11:22:33:44:55"]["is_guest"] is True


def test_unifi_client_get_guest_authorizations():
    client = UnifiControllerClient(
        url="https://10.0.0.1",
        api_key="my-key",
        site="default",
    )

    with patch.object(client.session, "get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "meta": {"rc": "ok"},
            "data": [
                {
                    "mac": "00:11:22:33:44:55",
                    "start": 1700000000,
                    "end": 1700086400,
                    "duration": 1440,
                }
            ]
        }
        mock_get.return_value = mock_resp

        guests = client.get_guest_authorizations()
        assert "00:11:22:33:44:55" in guests
        assert guests["00:11:22:33:44:55"]["end"] == 1700086400


def test_unifi_client_revoke_guest():
    client = UnifiControllerClient(
        url="https://10.0.0.1",
        api_key="my-key",
        site="default",
    )

    with patch.object(client.session, "post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"meta": {"rc": "ok"}}
        mock_post.return_value = mock_resp

        ok = client.revoke_guest("00:11:22:33:44:55")
        assert ok is True
        assert mock_post.call_count == 2
        # First call unauthorize-guest
        assert mock_post.call_args_list[0][1]["json"]["cmd"] == "unauthorize-guest"
        # Second call kick-sta
        assert mock_post.call_args_list[1][1]["json"]["cmd"] == "kick-sta"
