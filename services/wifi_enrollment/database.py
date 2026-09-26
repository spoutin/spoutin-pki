import os
import sqlite3
import threading
import time
from typing import Any, Optional


class CertificateDatabase:
    """Thread-safe SQLite storage for Wi-Fi certificate inventory and revocation state."""

    def __init__(self, db_path: str = "/opt/wifi-enrollment/data/inventory.db"):
        self.db_path = db_path
        if self.db_path != ":memory:":
            try:
                os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
            except (PermissionError, OSError):
                # Fallback to local working directory data folder if system path is not writable
                local_dir = os.path.abspath("./data")
                os.makedirs(local_dir, exist_ok=True)
                self.db_path = os.path.join(local_dir, "inventory.db")

        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            if self.db_path != ":memory:":
                cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS certificates (
                    serial_number TEXT PRIMARY KEY,
                    device_name TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    vlan_id INTEGER NOT NULL,
                    vlan_label TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    cert_pem TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    revoked_at INTEGER,
                    revocation_reason TEXT,
                    revocation_scope TEXT,
                    opnsense_uuid TEXT,
                    request_id TEXT
                );
                """
            )
            # Automatic schema migration for existing databases
            cur.execute("PRAGMA table_info(certificates)")
            cols = [col[1] for col in cur.fetchall()]
            if "request_id" not in cols:
                cur.execute("ALTER TABLE certificates ADD COLUMN request_id TEXT;")

            cur.execute("CREATE INDEX IF NOT EXISTS idx_device_name ON certificates(device_name);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_status ON certificates(status);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_vlan_id ON certificates(vlan_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_request_id ON certificates(request_id);")
            self._conn.commit()

    def insert_certificate(
        self,
        serial_number: str,
        device_name: str,
        platform: str,
        vlan_id: int,
        vlan_label: str,
        client_ip: str,
        cert_pem: str,
        issued_at: int,
        expires_at: int,
        opnsense_uuid: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                INSERT INTO certificates (
                    serial_number, device_name, platform, vlan_id, vlan_label,
                    client_ip, cert_pem, issued_at, expires_at, status, opnsense_uuid, request_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)
                ON CONFLICT(serial_number) DO UPDATE SET
                    device_name=excluded.device_name,
                    platform=excluded.platform,
                    vlan_id=excluded.vlan_id,
                    vlan_label=excluded.vlan_label,
                    client_ip=excluded.client_ip,
                    cert_pem=excluded.cert_pem,
                    issued_at=excluded.issued_at,
                    expires_at=excluded.expires_at,
                    status='ACTIVE',
                    opnsense_uuid=excluded.opnsense_uuid,
                    request_id=COALESCE(excluded.request_id, certificates.request_id);
                """,
                (
                    serial_number,
                    device_name,
                    platform,
                    vlan_id,
                    vlan_label,
                    client_ip,
                    cert_pem,
                    issued_at,
                    expires_at,
                    opnsense_uuid,
                    request_id,
                ),
            )
            self._conn.commit()

    def get_certificate(self, serial_number: str) -> Optional[dict[str, Any]]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT * FROM certificates WHERE serial_number = ?", (serial_number,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_certificates(
        self,
        status: Optional[str] = None,
        search: Optional[str] = None,
        vlan_id: Optional[int] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        with self._lock:
            query = "SELECT * FROM certificates WHERE 1=1"
            params: list[Any] = []

            if status:
                query += " AND status = ?"
                params.append(status.upper())

            if vlan_id is not None:
                query += " AND vlan_id = ?"
                params.append(vlan_id)

            if search:
                query += " AND (device_name LIKE ? OR serial_number LIKE ? OR client_ip LIKE ? OR request_id LIKE ?)"
                like_term = f"%{search}%"
                params.extend([like_term, like_term, like_term, like_term])

            query += " ORDER BY issued_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cur = self._conn.cursor()
            cur.execute(query, params)
            rows = cur.fetchall()
            return [dict(r) for r in rows]

    def device_name_exists(self, device_name: str) -> bool:
        """Checks if an active certificate exists for the given device name."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT 1 FROM certificates WHERE device_name = ? AND status = 'ACTIVE' LIMIT 1",
                (device_name,),
            )
            return cur.fetchone() is not None

    def get_certificate_by_device_name(self, device_name: str) -> Optional[dict[str, Any]]:
        """Retrieves the latest active certificate for a device name."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT * FROM certificates WHERE device_name = ? AND status = 'ACTIVE' ORDER BY issued_at DESC LIMIT 1",
                (device_name,),
            )
            row = cur.fetchone()
            return dict(row) if row else None

    def update_certificate_vlan(
        self,
        serial_number: str,
        vlan_id: int,
        vlan_label: str,
    ) -> bool:
        """Updates the assigned VLAN ID and label for a certificate."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                UPDATE certificates
                SET vlan_id = ?,
                    vlan_label = ?
                WHERE serial_number = ?
                """,
                (vlan_id, vlan_label, serial_number),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def update_vlan_by_device_name(
        self,
        device_name: str,
        vlan_id: int,
        vlan_label: str,
    ) -> int:
        """Updates the VLAN for all active certificates matching device_name."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                UPDATE certificates
                SET vlan_id = ?,
                    vlan_label = ?
                WHERE device_name = ? AND status = 'ACTIVE' AND vlan_id != ?
                """,
                (vlan_id, vlan_label, device_name, vlan_id),
            )
            self._conn.commit()
            return cur.rowcount

    def revoke_certificate(
        self,
        serial_number: str,
        reason: str = "cessationOfOperation",
        scope: str = "CERT_ONLY",
    ) -> bool:
        with self._lock:
            now = int(time.time())
            cur = self._conn.cursor()
            cur.execute(
                """
                UPDATE certificates
                SET status = 'REVOKED',
                    revoked_at = ?,
                    revocation_reason = ?,
                    revocation_scope = ?
                WHERE serial_number = ?
                """,
                (now, reason, scope, serial_number),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT COUNT(*) FROM certificates")
            total = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM certificates WHERE status = 'ACTIVE'")
            active = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM certificates WHERE status = 'REVOKED'")
            revoked = cur.fetchone()[0]

            cur.execute("SELECT vlan_id, COUNT(*) FROM certificates GROUP BY vlan_id")
            vlan_rows = cur.fetchall()
            by_vlan = {int(r[0]): r[1] for r in vlan_rows}

            return {
                "total": total,
                "active": active,
                "revoked": revoked,
                "by_vlan": by_vlan,
            }
