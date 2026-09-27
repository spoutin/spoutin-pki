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


@patch("requests.Session.post")
def test_list_users(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "rows": [
            {"username": "dev-1", "uuid": "u1", "vlan": "8", "enabled": "1"},
            {"username": "dev-2", "uuid": "u2", "vlan": "1", "enabled": "1"},
        ]
    }
    mock_post.return_value = mock_resp

    client = FreeRadiusClient("https://opnsense.local", "key", "secret")
    users = client.list_users()
    assert len(users) == 2
    assert users["dev-1"]["vlan"] == 8
    assert users["dev-2"]["vlan"] == 1


@patch("requests.Session.post")
def test_update_user_vlan_existing(mock_post):
    search_resp = MagicMock()
    search_resp.status_code = 200
    search_resp.json.return_value = {"rows": [{"username": "dev-1", "uuid": "u1"}]}

    set_resp = MagicMock()
    set_resp.status_code = 200
    set_resp.json.return_value = {"result": "saved"}

    reconfig_resp = MagicMock()
    reconfig_resp.status_code = 200
    reconfig_resp.json.return_value = {"status": "ok"}

    mock_post.side_effect = [search_resp, set_resp, reconfig_resp]

    client = FreeRadiusClient("https://opnsense.local", "key", "secret")
    assert client.update_user_vlan("dev-1", 1, description="Spoutin PKI | vlan:1 | req:123") is True
    set_call = mock_post.call_args_list[1]
    assert set_call.kwargs["json"]["user"]["description"] == "Spoutin PKI | vlan:1 | req:123"


@patch("requests.Session.post")
def test_upsert_user_existing(mock_post):
    search_resp = MagicMock()
    search_resp.status_code = 200
    search_resp.json.return_value = {"rows": [{"username": "dev-1", "uuid": "u1"}]}

    set_resp = MagicMock()
    set_resp.status_code = 200
    set_resp.json.return_value = {"result": "saved"}

    mock_post.side_effect = [search_resp, set_resp]

    client = FreeRadiusClient("https://opnsense.local", "key", "secret")
    res = client.upsert_user("dev-1", 8, description="Spoutin PKI | vlan:8 | req:abc")
    assert res == {"result": "saved"}
    set_call = mock_post.call_args_list[1]
    assert "/setUser/u1" in set_call.args[0]
    assert set_call.kwargs["json"]["user"]["vlan"] == "8"
    assert set_call.kwargs["json"]["user"]["description"] == "Spoutin PKI | vlan:8 | req:abc"


@patch("requests.Session.post")
def test_upsert_user_new(mock_post):
    search_resp = MagicMock()
    search_resp.status_code = 200
    search_resp.json.return_value = {"rows": []}

    add_resp = MagicMock()
    add_resp.status_code = 200
    add_resp.json.return_value = {"result": "saved"}

    mock_post.side_effect = [search_resp, add_resp]

    client = FreeRadiusClient("https://opnsense.local", "key", "secret")
    res = client.upsert_user("dev-new", 8, description="Spoutin PKI | vlan:8 | req:xyz")
    assert res == {"result": "saved"}
    add_call = mock_post.call_args_list[1]
    assert "/addUser" in add_call.args[0]
    assert add_call.kwargs["json"]["user"]["vlan"] == "8"
    assert add_call.kwargs["json"]["user"]["description"] == "Spoutin PKI | vlan:8 | req:xyz"


@patch("requests.Session.get")
@patch("requests.Session.post")
def test_push_crl_success(mock_post, mock_get):
    mock_post_resp = MagicMock()
    mock_post_resp.status_code = 200
    mock_post_resp.json.return_value = {"status": "saved"}
    mock_post.return_value = mock_post_resp

    mock_get_resp = MagicMock()
    mock_get_resp.status_code = 200
    mock_get_resp.json.return_value = {
        "eap": {
            "crl": {
                "crl-uuid-1": {"value": "Spoutin Wi-Fi CRL", "selected": 1}
            }
        }
    }
    mock_get.return_value = mock_get_resp

    client = FreeRadiusClient("https://opnsense.local", "key", "secret")
    success = client.push_crl("-----BEGIN X509 CRL-----\nMOCK\n-----END X509 CRL-----", caref="ca-inter-123")
    assert success is True

    call_args = mock_post.call_args_list[0]
    assert "/api/trust/crl/set/ca-inter-123" in call_args.args[0]
    assert call_args.kwargs["data"]["crl[crlmethod]"] == "existing"
    assert call_args.kwargs["data"]["crl[descr]"] == "Spoutin Wi-Fi CRL"


@patch("requests.Session.post")
def test_restart_service_success(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_post.return_value = mock_resp

    client = FreeRadiusClient("https://opnsense.local", "key", "secret")
    assert client.restart_service() is True
    assert "/api/freeradius/service/restart" in mock_post.call_args.args[0]


@patch("requests.Session.get")
def test_get_intermediate_ca_refid(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "rows": [
            {"descr": "Root CA", "refid": "root-1"},
            {"descr": "step-ca Intermediate CA", "refid": "inter-2"},
        ]
    }
    mock_get.return_value = mock_resp

    client = FreeRadiusClient("https://opnsense.local", "key", "secret")
    assert client.get_intermediate_ca_refid() == "inter-2"


