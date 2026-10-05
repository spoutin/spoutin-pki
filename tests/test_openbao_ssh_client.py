import pytest
from unittest.mock import MagicMock, patch
from services.pki.openbao_client import OpenBaoCaClient


@pytest.fixture
def mock_openbao():
    return OpenBaoCaClient(
        base_url="https://secrets.example.com:8200",
        token="s.mock-token",
        pki_mount="pki",
        role_name="wifi-client",
        verify_ssl=False,
    )


def test_get_ssh_ca_public_key(mock_openbao):
    with patch.object(mock_openbao.session, "get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {"public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICA_mock_ca_key"}
        }
        mock_get.return_value = mock_resp

        ca_pub = mock_openbao.get_ssh_ca_public_key()
        assert ca_pub.startswith("ssh-ed25519")
        mock_get.assert_called_with(
            "https://secrets.example.com:8200/v1/ssh/config/ca",
            headers={"X-Vault-Token": "s.mock-token"},
            timeout=10,
        )


def test_sign_ssh_public_key(mock_openbao):
    with patch.object(mock_openbao.session, "post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "serial_number": "1234567890",
                "signed_key": "ssh-ed25519-cert-v01@openssh.com AAAA... mock_cert",
            }
        }
        mock_post.return_value = mock_resp

        res = mock_openbao.sign_ssh_public_key(
            public_key="ssh-ed25519 AAAAB3... user_pub",
            key_id="ablack",
            principals=["ablack", "root", "operator"],
            ttl="70080h",
            role="admin-user",
        )
        assert res["serial_number"] == "1234567890"
        assert res["signed_key"].startswith("ssh-ed25519-cert-v01")
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert args[0] == "https://secrets.example.com:8200/v1/ssh/sign/admin-user"
        assert kwargs["json"]["key_id"] == "ablack"
        assert kwargs["json"]["valid_principals"] == "ablack,root,operator"
        assert kwargs["json"]["ttl"] == "70080h"
