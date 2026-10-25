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
    ):
        self.url = url.rstrip("/")
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

    def revoke_guest(self, mac: str) -> bool:
        """De-authorizes guest and kicks station from AP."""
        norm_mac = mac.lower().strip()
        # 1. Unauthorize guest
        unauth_ok = self._post_api("cmd/stamgr", {"cmd": "unauthorize-guest", "mac": norm_mac})
        # 2. Kick station
        kick_ok = self._post_api("cmd/stamgr", {"cmd": "kick-sta", "mac": norm_mac})
        return unauth_ok or kick_ok
