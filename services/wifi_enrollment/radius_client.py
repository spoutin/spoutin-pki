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

    def get_user_uuid(self, username: str) -> Optional[str]:
        """Finds and returns the OPNsense internal UUID for a FreeRADIUS user."""
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
            for row in data.get("rows", []):
                if row.get("username") == username:
                    return row.get("uuid")
        except Exception:
            pass
        return None

    def delete_user(self, username: str) -> bool:
        """Deletes a user from OPNsense FreeRADIUS and reconfigures the service."""
        user_uuid = self.get_user_uuid(username)
        if not user_uuid:
            return True

        endpoint = f"{self.url}/api/freeradius/user/delUser/{user_uuid}"
        resp = self.session.post(
            endpoint,
            auth=self.auth,
            verify=self.verify_ssl,
            json={},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("result") in ("deleted", "not found"):
            self.reconfigure_service()
            return True
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

    def list_users(self) -> dict[str, dict]:
        """Returns all FreeRADIUS users and their configured VLANs from OPNsense."""
        endpoint = f"{self.url}/api/freeradius/user/searchUser"
        try:
            resp = self.session.post(
                endpoint,
                auth=self.auth,
                verify=self.verify_ssl,
                json={"rowCount": -1, "searchPhrase": ""},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            users: dict[str, dict] = {}
            for row in data.get("rows", []):
                username = row.get("username")
                if not username:
                    continue
                vlan_raw = row.get("vlan")
                vlan_int = int(vlan_raw) if vlan_raw is not None and str(vlan_raw).isdigit() else None
                users[username] = {
                    "uuid": row.get("uuid"),
                    "vlan": vlan_int,
                    "enabled": row.get("enabled"),
                    "description": row.get("description"),
                }
            return users
        except Exception:
            return {}

    def update_user_vlan(self, username: str, vlan: int) -> bool:
        """Updates the Dynamic VLAN assignment for an existing FreeRADIUS user and reconfigures."""
        user_uuid = self.get_user_uuid(username)
        if not user_uuid:
            # Fallback to adding the user if not found
            self.add_user(username=username, vlan=vlan)
            self.reconfigure_service()
            return True

        endpoint = f"{self.url}/api/freeradius/user/setUser/{user_uuid}"
        payload = {
            "user": {
                "vlan": str(vlan),
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
        if data.get("result") == "saved":
            self.reconfigure_service()
            return True
        return False

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
