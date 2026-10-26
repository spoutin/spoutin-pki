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


def test_unifi_client_get_user_groups():
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
                    "_id": "group1",
                    "name": "Default",
                    "qos_rate_max_down": -1,
                    "qos_rate_max_up": -1,
                },
                {
                    "_id": "group2",
                    "name": "Guest-Limited",
                    "qos_rate_max_down": 10000,
                    "qos_rate_max_up": 5000,
                },
            ],
        }
        mock_get.return_value = mock_resp

        groups = client.get_user_groups()
        assert len(groups) == 2
        assert groups[0] == {
            "id": "group1",
            "name": "Default",
            "down_kbps": -1,
            "up_kbps": -1,
        }
        assert groups[1] == {
            "id": "group2",
            "name": "Guest-Limited",
            "down_kbps": 10000,
            "up_kbps": 5000,
        }


def test_unifi_client_get_client():
    client = UnifiControllerClient(
        url="https://10.0.0.1",
        api_key="my-key",
        site="default",
    )

    # 1. Found via stat/user/{mac}
    with patch.object(client.session, "get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "u123", "mac": "00:11:22:33:44:55", "name": "Device 1"}],
        }
        mock_get.return_value = mock_resp

        res = client.get_client("00:11:22:33:44:55")
        assert res is not None
        assert res["_id"] == "u123"

    # 2. Not in stat/user, fallback to stat/sta
    with patch.object(client.session, "get") as mock_get:
        resp_empty = MagicMock()
        resp_empty.ok = True
        resp_empty.status_code = 200
        resp_empty.json.return_value = {"meta": {"rc": "ok"}, "data": []}

        resp_sta = MagicMock()
        resp_sta.ok = True
        resp_sta.status_code = 200
        resp_sta.json.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "sta123", "mac": "00:11:22:33:44:55"}],
        }

        # Sequence of calls: stat/user/{mac} returns empty, then stat/sta returns client
        mock_get.side_effect = [resp_empty, resp_sta]

        res = client.get_client("00:11:22:33:44:55")
        assert res is not None
        assert res["_id"] == "sta123"

    # 3. Not found anywhere
    with patch.object(client.session, "get") as mock_get:
        resp_empty = MagicMock()
        resp_empty.ok = True
        resp_empty.status_code = 200
        resp_empty.json.return_value = {"meta": {"rc": "ok"}, "data": []}
        mock_get.side_effect = [resp_empty, resp_empty, resp_empty]

        res = client.get_client("aa:bb:cc:dd:ee:ff")
        assert res is None


def test_unifi_client_set_client_user_group():
    client = UnifiControllerClient(
        url="https://10.0.0.1",
        api_key="my-key",
        site="default",
    )

    # 1. Existing user -> PUT rest/user/{user_id} succeeds
    with patch.object(client, "get_client") as mock_get_client, patch.object(
        client, "_put_api"
    ) as mock_put:
        mock_get_client.return_value = {"_id": "user123", "mac": "00:11:22:33:44:55"}
        mock_put.return_value = True

        ok = client.set_client_user_group("00:11:22:33:44:55", "group_fast")
        assert ok is True
        mock_put.assert_called_once_with("rest/user/user123", {"usergroup_id": "group_fast"})

    # 2. Existing user -> PUT fails, fallback to POST upd/user/{user_id}
    with patch.object(client, "get_client") as mock_get_client, patch.object(
        client, "_put_api"
    ) as mock_put, patch.object(client, "_post_api") as mock_post:
        mock_get_client.return_value = {"_id": "user123", "mac": "00:11:22:33:44:55"}
        mock_put.return_value = False
        mock_post.return_value = True

        ok = client.set_client_user_group("00:11:22:33:44:55", "group_fast")
        assert ok is True
        mock_put.assert_called_once_with("rest/user/user123", {"usergroup_id": "group_fast"})
        mock_post.assert_called_once_with("upd/user/user123", {"usergroup_id": "group_fast"})

    # 3. Non-existing user -> create via POST rest/user
    with patch.object(client, "get_client") as mock_get_client, patch.object(
        client, "_post_api"
    ) as mock_post:
        mock_get_client.return_value = None
        mock_post.return_value = True

        ok = client.set_client_user_group("00:11:22:33:44:55", "group_fast")
        assert ok is True
        mock_post.assert_called_once_with(
            "rest/user", {"mac": "00:11:22:33:44:55", "usergroup_id": "group_fast"}
        )


def test_unifi_client_authorize_guest():
    client = UnifiControllerClient(
        url="https://10.0.0.1",
        api_key="my-key",
        site="default",
    )

    with patch.object(client, "_post_api") as mock_post:
        mock_post.return_value = True

        # Without bandwidth limits
        ok = client.authorize_guest("00:11:22:33:44:55", 120)
        assert ok is True
        mock_post.assert_called_with(
            "cmd/stamgr",
            {
                "cmd": "authorize-guest",
                "mac": "00:11:22:33:44:55",
                "minutes": 120,
            },
        )

        # With bandwidth limits
        ok = client.authorize_guest(
            "00:11:22:33:44:55",
            120,
            up_kbps=5000,
            down_kbps=10000,
        )
        assert ok is True
        mock_post.assert_called_with(
            "cmd/stamgr",
            {
                "cmd": "authorize-guest",
                "mac": "00:11:22:33:44:55",
                "minutes": 120,
                "up": 5000,
                "down": 10000,
            },
        )

        # With bandwidth limits zero/negative (should not be included)
        ok = client.authorize_guest(
            "00:11:22:33:44:55",
            60,
            up_kbps=0,
            down_kbps=-1,
        )
        assert ok is True
        mock_post.assert_called_with(
            "cmd/stamgr",
            {
                "cmd": "authorize-guest",
                "mac": "00:11:22:33:44:55",
                "minutes": 60,
            },
        )
