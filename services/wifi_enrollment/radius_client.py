import secrets
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FreeRadiusClient:
    """Client for OPNsense os-freeradius REST API."""

    def __init__(
        self,
        url: str,
        api_key: str,
        api_secret: str,
        verify_ssl: bool = False,
    ):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.api_secret = api_secret
        self.verify_ssl = verify_ssl
        self.auth = (self.api_key, self.api_secret)

        self.session = requests.Session()
        self.session.trust_env = False

    def user_exists(self, username: str) -> bool:
        """Checks if a user/CN already exists in FreeRADIUS."""
        endpoint = f"{self.url}/api/freeradius/user/searchUser"
        try:
            resp = self.session.post(
                endpoint,
                auth=self.auth,
                verify=self.verify_ssl,
                json={"searchPhrase": username},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            rows = data.get("rows", [])
            return any(row.get("username") == username for row in rows)
        except Exception as e:
            # If search fails, log or raise appropriately
            return False

    def add_user(
        self,
        username: str,
        vlan: int,
        description: str = "Auto-enrolled via wifi-enrollment",
        password: Optional[str] = None,
    ) -> dict:
        """Adds a user with an assigned Dynamic VLAN into FreeRADIUS."""
        endpoint = f"{self.url}/api/freeradius/user/addUser"

        # EAP-TLS client authentication doesn't use passwords, but OPNsense model requires it
        user_password = password or secrets.token_urlsafe(16)

        payload = {
            "user": {
                "enabled": "1",
                "username": username,
                "password": user_password,
                "passwordencryption": "Cleartext-Password",
                "vlan": str(vlan),
                "description": description,
            }
        }

        resp = self.session.post(
            endpoint,
            auth=self.auth,
            verify=self.verify_ssl,
            json=payload,
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("result") != "saved":
            raise RuntimeError(f"Failed to add FreeRADIUS user '{username}': {data}")

        return data

    def reconfigure_service(self) -> bool:
        """Regenerates FreeRADIUS configuration templates and reloads the daemon."""
        endpoint = f"{self.url}/api/freeradius/service/reconfigure"
        resp = self.session.post(
            endpoint,
            auth=self.auth,
            verify=self.verify_ssl,
            json={},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("status") == "ok"
