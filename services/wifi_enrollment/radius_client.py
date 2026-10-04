import logging
import secrets
from typing import Any, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class FreeRadiusClient:
    """Client for OPNsense os-freeradius REST API."""

    def __init__(
        self,
        url: str,
        api_key: str,
        api_secret: str,
        verify_ssl: bool = False,
        intermediate_ca_refid: Optional[str] = None,
    ):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.api_secret = api_secret
        self.verify_ssl = verify_ssl
        self.intermediate_ca_refid = intermediate_ca_refid
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
                json={"searchPhrase": username, "rowCount": -1},
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
                json={"searchPhrase": username, "rowCount": -1},
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
        if data.get("result") in ("saved", "ok"):
            return data
        raise RuntimeError(f"Failed to add FreeRADIUS user: {data}")

    def upsert_user(
        self,
        username: str,
        vlan: int,
        description: str = "Auto-enrolled via wifi-enrollment",
        password: Optional[str] = None,
    ) -> dict:
        """Adds a new user or updates an existing user in FreeRADIUS to prevent duplicates."""
        user_uuid = self.get_user_uuid(username)
        if user_uuid:
            logger.info("FreeRADIUS user '%s' already exists (UUID: %s); updating VLAN and description.", username, user_uuid)
            endpoint = f"{self.url}/api/freeradius/user/setUser/{user_uuid}"
            payload = {
                "user": {
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
            return resp.json()
        else:
            return self.add_user(
                username=username,
                vlan=vlan,
                description=description,
                password=password,
            )

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

    def update_user_vlan(self, username: str, vlan: int, description: Optional[str] = None) -> bool:
        """Updates the Dynamic VLAN assignment (and optionally description) for an existing FreeRADIUS user and reconfigures."""
        user_uuid = self.get_user_uuid(username)
        if not user_uuid:
            # Fallback to adding the user if not found
            self.add_user(username=username, vlan=vlan, description=description or "Auto-enrolled via wifi-enrollment")
            self.reconfigure_service()
            return True

        endpoint = f"{self.url}/api/freeradius/user/setUser/{user_uuid}"
        payload_user: dict[str, Any] = {"vlan": str(vlan)}
        if description:
            payload_user["description"] = description
        payload = {"user": payload_user}
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

    def restart_service(self) -> bool:
        """Restarts the FreeRADIUS daemon via OPNsense API to reload certificates/CRLs."""
        endpoint = f"{self.url}/api/freeradius/service/restart"
        resp = self.session.post(
            endpoint,
            auth=self.auth,
            verify=self.verify_ssl,
            json={},
            timeout=15,
        )
        resp.raise_for_status()
        return True

    def get_intermediate_ca_refid(self) -> Optional[str]:
        """Discovers the refid of the intermediate Certificate Authority in OPNsense."""
        if self.intermediate_ca_refid:
            return self.intermediate_ca_refid

        endpoint = f"{self.url}/api/trust/ca/search/"
        try:
            resp = self.session.get(endpoint, auth=self.auth, verify=self.verify_ssl, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            for row in data.get("rows", []):
                descr = (row.get("descr") or "").lower()
                name = (row.get("name") or "").lower()
                if any(k in descr or k in name for k in ("openbao", "vault", "infisical", "intermediate", "step-ca", "spoutin")):
                    return row.get("refid")
        except Exception as e:
            logger.warning("Failed to auto-discover intermediate CA refid: %s", e)
        return None

    def push_crl(
        self,
        crl_pem: str | bytes,
        caref: Optional[str] = None,
        descr: str = "Spoutin Wi-Fi CRL",
    ) -> bool:
        """Pushes an updated CRL into OPNsense Trust and ensures FreeRADIUS EAP is linked."""
        target_caref = caref or self.get_intermediate_ca_refid()
        if not target_caref:
            logger.error("Cannot push CRL: no intermediate CA refid found in OPNsense.")
            return False
        crl_pem_str = crl_pem.decode("utf-8") if isinstance(crl_pem, bytes) else crl_pem

        endpoint = f"{self.url}/api/trust/crl/set/{target_caref}"
        data = {
            "crl[crlmethod]": "existing",
            "crl[descr]": descr,
            "crl[text]": crl_pem_str,
            "crl[lifetime]": "9999",
        }
        resp = self.session.post(
            endpoint,
            auth=self.auth,
            verify=self.verify_ssl,
            data=data,
            timeout=15,
        )
        resp.raise_for_status()
        res_json = resp.json()
        if res_json.get("status") != "saved":
            logger.error("Failed to save CRL to OPNsense: %s", res_json)
            return False

        self._ensure_eap_crl_selected(descr)
        return True

    def _ensure_eap_crl_selected(self, descr: str = "Spoutin Wi-Fi CRL") -> None:
        """Ensures the CRL is actively selected in FreeRADIUS EAP configuration."""
        try:
            get_resp = self.session.get(
                f"{self.url}/api/freeradius/eap/get",
                auth=self.auth,
                verify=self.verify_ssl,
                timeout=10,
            )
            get_resp.raise_for_status()
            eap_data = get_resp.json()
            crl_map = eap_data.get("eap", {}).get("crl", {})
            for refid, item in crl_map.items():
                if item.get("value") == descr:
                    if item.get("selected") != 1:
                        set_resp = self.session.post(
                            f"{self.url}/api/freeradius/eap/set",
                            auth=self.auth,
                            verify=self.verify_ssl,
                            json={"eap": {"crl": refid, "enable_client_cert": "1"}},
                            timeout=10,
                        )
                        set_resp.raise_for_status()
                    break
        except Exception as e:
            logger.warning("Could not verify or set EAP CRL link: %s", e)
