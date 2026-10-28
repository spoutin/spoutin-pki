import logging
from typing import Any, Optional
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


class UnifiControllerClient:
    """Client for Ubiquiti UniFi OS / Controller REST APIs."""

    def __init__(
        self,
        url: str = "",
        api_key: str = "",
        username: str = "",
        password: str = "",
        site: str = "default",
        verify_ssl: bool = False,
        base_url: Optional[str] = None,
    ):
        target_url = base_url if base_url is not None else url
        self.url = target_url.rstrip("/")
        self.base_url = self.url
        self.api_key = api_key
        self.username = username
        self.password = password
        self.site = site
        self.verify_ssl = verify_ssl

        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.trust_env = False

        if self.api_key:
            self.session.headers.update({"X-API-KEY": self.api_key})

        self._csrf_token: Optional[str] = None

    def _login_if_needed(self) -> None:
        if self.api_key or not self.url or not self.username:
            return

        login_url = f"{self.url}/api/auth/login"
        payload = {"username": self.username, "password": self.password}
        try:
            resp = self.session.post(login_url, json=payload, timeout=10)
            if resp.status_code == 404:
                # Standalone controller login endpoint
                login_url = f"{self.url}/api/login"
                resp = self.session.post(login_url, json=payload, timeout=10)
            resp.raise_for_status()
            token = resp.headers.get("X-CSRF-Token")
            if token:
                self._csrf_token = token
                self.session.headers.update({"X-CSRF-Token": token})
        except Exception as e:
            logger.warning(f"UniFi login failed: {e}")

    def _get_api(self, subpath: str) -> Optional[dict[str, Any]]:
        if not self.url:
            return None
        self._login_if_needed()

        endpoints = [
            f"{self.url}/proxy/network/api/s/{self.site}/{subpath.lstrip('/')}",
            f"{self.url}/api/s/{self.site}/{subpath.lstrip('/')}",
        ]

        for url in endpoints:
            try:
                resp = self.session.get(url, timeout=10)
                if resp.status_code == 404 and url == endpoints[0]:
                    continue
                resp.raise_for_status()
                return resp.json()
            except Exception as e:
                logger.warning(f"UniFi GET {url} failed: {e}")
        return None

    def _post_api(self, subpath: str, data: dict[str, Any]) -> bool:
        if not self.url:
            return False
        self._login_if_needed()

        endpoints = [
            f"{self.url}/proxy/network/api/s/{self.site}/{subpath.lstrip('/')}",
            f"{self.url}/api/s/{self.site}/{subpath.lstrip('/')}",
        ]

        for url in endpoints:
            try:
                resp = self.session.post(url, json=data, timeout=10)
                if resp.status_code == 404 and url == endpoints[0]:
                    continue
                resp.raise_for_status()
                res_data = resp.json()
                return res_data.get("meta", {}).get("rc") == "ok"
            except Exception as e:
                logger.warning(f"UniFi POST {url} failed: {e}")
        return False

    def _put_api(self, subpath: str, data: dict[str, Any]) -> bool:
        if not self.url:
            return False
        self._login_if_needed()

        endpoints = [
            f"{self.url}/proxy/network/api/s/{self.site}/{subpath.lstrip('/')}",
            f"{self.url}/api/s/{self.site}/{subpath.lstrip('/')}",
        ]

        for url in endpoints:
            try:
                resp = self.session.put(url, json=data, timeout=10)
                if resp.status_code == 404 and url == endpoints[0]:
                    continue
                resp.raise_for_status()
                res_data = resp.json()
                return res_data.get("meta", {}).get("rc") == "ok"
            except Exception as e:
                logger.warning(f"UniFi PUT {url} failed: {e}")
        return False

    def get_active_clients(self) -> dict[str, dict[str, Any]]:
        """Returns map of MAC -> active client dictionary from stat/sta."""
        res = self._get_api("stat/sta")
        clients = {}
        if res and isinstance(res.get("data"), list):
            for item in res["data"]:
                mac = item.get("mac", "").lower().strip()
                if mac:
                    clients[mac] = item
        return clients

    def get_guest_authorizations(self) -> dict[str, dict[str, Any]]:
        """Returns map of MAC -> guest auth info from stat/guest."""
        res = self._get_api("stat/guest")
        guests = {}
        if res and isinstance(res.get("data"), list):
            for item in res["data"]:
                mac = item.get("mac", "").lower().strip()
                if mac:
                    guests[mac] = item
        return guests

    def get_all_guests(self) -> list[dict[str, Any]]:
        """Returns raw list of all guest objects from stat/guest."""
        res = self._get_api("stat/guest")
        if res and isinstance(res.get("data"), list):
            return res["data"]
        return []

    def get_user_groups(self) -> list[dict[str, Any]]:
        """Fetch list of user groups / bandwidth profiles configured on the controller."""
        res = self._get_api("rest/usergroup")
        groups = []
        if res and isinstance(res.get("data"), list):
            for item in res["data"]:
                groups.append({
                    "id": item.get("_id"),
                    "name": item.get("name"),
                    "down_kbps": item.get("qos_rate_max_down", -1),
                    "up_kbps": item.get("qos_rate_max_up", -1),
                })
        return groups

    def get_client_usergroups_map(self) -> dict[str, str]:
        """Fetch map of client MAC -> usergroup_id from rest/user and stat/sta."""
        result: dict[str, str] = {}
        res_users = self._get_api("rest/user")
        if res_users and isinstance(res_users.get("data"), list):
            for item in res_users["data"]:
                if isinstance(item, dict):
                    mac = item.get("mac", "").lower().strip()
                    ug_id = item.get("usergroup_id")
                    if mac and ug_id:
                        result[mac] = str(ug_id)

        res_sta = self._get_api("stat/sta")
        if res_sta and isinstance(res_sta.get("data"), list):
            for item in res_sta["data"]:
                if isinstance(item, dict):
                    mac = item.get("mac", "").lower().strip()
                    ug_id = item.get("usergroup_id")
                    if mac and ug_id:
                        result[mac] = str(ug_id)

        return result

    def get_client(self, mac: str) -> Optional[dict[str, Any]]:
        """Look up client device / user record by MAC address."""
        norm_mac = mac.lower().strip()
        # Try stat/user/{mac} first
        res = self._get_api(f"stat/user/{norm_mac}")
        if res and isinstance(res.get("data"), list) and res["data"]:
            return res["data"][0]

        # Fallback to stat/sta to check active stations
        active_clients = self.get_active_clients()
        if norm_mac in active_clients:
            return active_clients[norm_mac]

        # Fallback to querying rest/user
        res_users = self._get_api("rest/user")
        if res_users and isinstance(res_users.get("data"), list):
            for item in res_users["data"]:
                if item.get("mac", "").lower().strip() == norm_mac:
                    return item

        return None

    def set_client_user_group(self, mac: str, usergroup_id: str) -> bool:
        """Assign a user group / speed profile to a client by MAC address."""
        norm_mac = mac.lower().strip()
        client = self.get_client(norm_mac)

        if client and client.get("_id"):
            user_id = client["_id"]
            # Try PUT rest/user/{user_id}
            if self._put_api(f"rest/user/{user_id}", {"usergroup_id": usergroup_id}):
                return True
            # Fallback to upd/user/{user_id}
            return self._post_api(f"upd/user/{user_id}", {"usergroup_id": usergroup_id})

        # User doesn't exist in rest/user yet, create or set via rest/user
        return self._post_api("rest/user", {"mac": norm_mac, "usergroup_id": usergroup_id})

    def authorize_guest(
        self,
        mac: str,
        duration_minutes: int,
        up_kbps: Optional[int] = None,
        down_kbps: Optional[int] = None,
    ) -> bool:
        """Authorizes guest station on the UniFi controller for given minutes with optional rate limits."""
        norm_mac = mac.lower().strip()
        payload: dict[str, Any] = {
            "cmd": "authorize-guest",
            "mac": norm_mac,
            "minutes": duration_minutes,
        }
        if up_kbps is not None and up_kbps > 0:
            payload["up"] = up_kbps
        if down_kbps is not None and down_kbps > 0:
            payload["down"] = down_kbps
        return self._post_api("cmd/stamgr", payload)

    def revoke_guest(self, mac: str) -> bool:
        """De-authorizes guest and kicks station from AP."""
        norm_mac = mac.lower().strip()
        # 1. Unauthorize guest
        unauth_ok = self._post_api("cmd/stamgr", {"cmd": "unauthorize-guest", "mac": norm_mac})
        # 2. Kick station
        kick_ok = self._post_api("cmd/stamgr", {"cmd": "kick-sta", "mac": norm_mac})
        return unauth_ok or kick_ok

    def set_client_name(self, mac: str, name: str) -> bool:
        """Sets client alias / display name in UniFi."""
        norm_mac = mac.lower().strip()
        cleaned_name = name.strip()
        if not cleaned_name:
            return False

        try:
            # 1. Look in active stations first
            sta_data = self._get_api("stat/sta")
            if sta_data:
                stations = sta_data.get("data", [])
                match = next((s for s in stations if s.get("mac", "").lower() == norm_mac), None)
                if match and match.get("_id"):
                    user_id = match["_id"]
                    self._post_api(f"upd/user/{user_id}", {"name": cleaned_name})
                    self._put_api(f"rest/user/{user_id}", {"name": cleaned_name})
                    return True

            # 2. Look in user list
            user_data = self._get_api("rest/user")
            if user_data:
                users = user_data.get("data", [])
                match = next((u for u in users if u.get("mac", "").lower() == norm_mac), None)
                if match and match.get("_id"):
                    user_id = match["_id"]
                    self._put_api(f"rest/user/{user_id}", {"name": cleaned_name})
                    self._post_api(f"upd/user/{user_id}", {"name": cleaned_name})
                    return True

            # 3. Create user record if doesn't exist
            return self._post_api("rest/user", {"mac": norm_mac, "name": cleaned_name})
        except Exception as e:
            logger.warning(f"UniFi set_client_name failed for {norm_mac}: {e}")
            return False
