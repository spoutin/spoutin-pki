# Certificate Management, Revocation & Admin Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an authenticated administrative web portal (`/admin`) with "Sign in with Slack" OAuth, persistent SQLite certificate inventory, real-time pending request approval/rejection (with Slack synchronization), two-option certificate revocation (Certificate Only vs. Certificate + FreeRADIUS User), and `step-ca` CRL generation and distribution.

**Architecture:**
* **Authentication:** Slack OpenID Connect OAuth (`openid email profile`), restricted to `ADMIN_SLACK_EMAILS` with secure HttpOnly JWT session cookies.
* **Persistent Inventory:** Embedded SQLite database (`/opt/wifi-enrollment/data/inventory.db`) tracking all issued certificates, serial numbers, VLANs, and revocation history.
* **Web Approval:** Allows admins to approve or reject pending requests directly from `/admin`. Upon web approval, the backend signs the certificate, records it in SQLite, and updates the Slack channel card in-place (`✅ Approved by @admin via Web Dashboard`).
* **Two-Option Revocation:**
  1. *Revoke Certificate Only:* Submits revocation to `step-ca` (`POST /1.0/revoke`), updating the CRL without modifying FreeRADIUS user records.
  2. *Revoke Certificate & Delete FreeRADIUS User:* Submits revocation to `step-ca` CRL AND deletes the user from OPNsense FreeRADIUS (`POST /api/freeradius/user/delUser/{uuid}`) and reconfigures the daemon.
  *(Per your instruction, no Slack alert is sent for revocations; state is updated directly in the database).*
* **CRL Distribution:** Caddy and the service expose `/crl` (reverse proxied to `step-ca:9000/crl`) so FreeRADIUS can validate revoked serials.

**Tech Stack:** Python 3.11 (`uv`), FastAPI, SQLite3, `cryptography`, `requests`, Slack OAuth/OIDC, Caddy.

## Global Constraints
* **Language & Package Manager:** Python `>=3.10` managed via `uv`.
* **Zero External DB Dependencies:** Use Python's built-in `sqlite3` engine with WAL mode for zero-configuration, robust persistence.
* **Security & Auth:** Admin routes under `/admin` and `/api/admin/*` must strictly require a valid Slack OAuth session cookie matching `ADMIN_SLACK_EMAILS`.
* **No Revocation Slack Alerts:** Revocations are recorded in the database, `step-ca` CRL, and FreeRADIUS without spamming Slack channels.
* **Bi-Directional Slack Updates:** Approving a request on the web dashboard updates the existing Slack channel card to reflect the approval.

---

### Task 1: Persistent Certificate Database (`database.py`)

**Files:**
* Create: `services/wifi_enrollment/database.py`
* Test: `tests/test_database.py`

**Interfaces:**
* `Database.insert_certificate(serial_number, device_name, platform, vlan_id, vlan_label, client_ip, cert_pem, opnsense_uuid=None)`
* `Database.list_certificates(status=None, search=None, vlan_id=None) -> list[dict]`
* `Database.get_certificate(serial_number) -> dict | None`
* `Database.revoke_certificate(serial_number, reason, scope: str)`
* `Database.get_stats() -> dict` (total, active, revoked, by_vlan)

- [ ] **Step 1: Write failing unit test for database schema and operations**
- [ ] **Step 2: Implement `database.py` using SQLite**
- [ ] **Step 3: Run tests and verify PASS**
- [ ] **Step 4: Commit**

---

### Task 2: Slack OAuth Authentication Module (`auth.py`)

**Files:**
* Create: `services/wifi_enrollment/auth.py`
* Modify: `services/wifi_enrollment/config.py`
* Test: `tests/test_auth.py`

**Interfaces:**
* `Settings`: Add `SLACK_CLIENT_ID`, `SLACK_CLIENT_SECRET`, `ADMIN_SLACK_EMAILS`, and `SESSION_SECRET_KEY`.
* `generate_oauth_url(state: str) -> str`
* `exchange_code_for_user(code: str) -> dict`
* `create_session_token(email: str, name: str) -> str`
* `verify_session_token(token: str) -> dict | None`
* `get_current_admin(request: Request) -> dict`

- [ ] **Step 1: Write failing unit test for Slack OAuth token creation, verification, and email authorization**
- [ ] **Step 2: Implement `auth.py` and update `config.py`**
- [ ] **Step 3: Run tests and verify PASS**
- [ ] **Step 4: Commit**

---

### Task 3: `step-ca` Revocation API Client & CRL Extension

**Files:**
* Modify: `services/wifi_enrollment/step_client.py`
* Test: `tests/test_step_client.py`

**Interfaces:**
* `StepCaClient.revoke_certificate(serial_number: str, reason: str = "cessationOfOperation", reason_code: int = 5) -> bool`
* `StepCaClient.generate_revocation_token(serial_number: str) -> str`
* `StepCaClient.get_crl() -> bytes`

- [ ] **Step 1: Write failing unit test for revocation token generation and `POST /1.0/revoke`**
- [ ] **Step 2: Implement `revoke_certificate` and `get_crl` in `StepCaClient`**
- [ ] **Step 3: Run tests and verify PASS**
- [ ] **Step 4: Commit**

---

### Task 4: OPNsense FreeRADIUS User Deletion & UUID Tracking

**Files:**
* Modify: `services/wifi_enrollment/radius_client.py`
* Test: `tests/test_radius_client.py`

**Interfaces:**
* `FreeRadiusClient.get_user_uuid(username: str) -> str | None`
* `FreeRadiusClient.delete_user(username: str) -> bool`

- [ ] **Step 1: Write failing unit test for user deletion in OPNsense**
- [ ] **Step 2: Implement `get_user_uuid` and `delete_user` in `FreeRadiusClient`**
- [ ] **Step 3: Run tests and verify PASS**
- [ ] **Step 4: Commit**

---

### Task 5: Admin API Endpoints & Request Synchronization in `server.py`

**Files:**
* Modify: `services/wifi_enrollment/server.py`
* Modify: `services/wifi_enrollment/slack_handler.py`
* Test: `tests/test_admin_server.py`

**Interfaces:**
* `GET /admin/login`: Renders Slack OAuth login page.
* `GET /admin/auth/login`: Redirects to Slack authorization endpoint.
* `GET /admin/auth/callback`: Handles OAuth redirect, sets cookie, redirects to `/admin`.
* `POST /admin/auth/logout`: Clears session cookie.
* `GET /api/admin/stats`: Returns KPI metrics (Active, Revoked, VLAN breakdown).
* `GET /api/admin/requests`: Returns live pending requests from `state_manager`.
* `POST /api/admin/requests/{request_id}/approve`: Approves pending request from web, mints cert, saves to SQLite, updates Slack card in-place, and satisfies client waiting on Wi-Fi page.
* `POST /api/admin/requests/{request_id}/reject`: Rejects request from web and updates Slack card.
* `GET /api/admin/certificates`: Lists certificates from SQLite with search and status filters.
* `POST /api/admin/certificates/{serial}/revoke`: Executes revocation with scope (`CERT_ONLY` vs `USER_AND_CERT`).
* `GET /crl`: Proxies or streams CRL from `step-ca` for FreeRADIUS.

- [ ] **Step 1: Write failing tests for admin endpoints**
- [ ] **Step 2: Implement admin endpoints in `server.py` and hook approval to `database.py`**
- [ ] **Step 3: Run tests and verify PASS**
- [ ] **Step 4: Commit**

---

### Task 6: Admin Web Dashboard & Login Frontend

**Files:**
* Create: `services/wifi_enrollment/static/admin.html`
* Create: `services/wifi_enrollment/static/admin.js`
* Create: `services/wifi_enrollment/static/admin.css`
* Create: `services/wifi_enrollment/static/admin_login.html`

- [ ] **Step 1: Build `admin_login.html`**
- [ ] **Step 2: Build `admin.html` & `admin.css`**
- [ ] **Step 3: Implement `admin.js`**

---

### Task 7: Infrastructure & Caddy Configuration

**Files:**
* Modify: `infra/caddy/Caddyfile`
* Modify: `infra/step-ca/ca.json.example`
* Modify: `README.md`

- [ ] **Step 1: Update `Caddyfile` with `/crl` reverse proxy**
- [ ] **Step 2: Update `ca.json.example` with CRL configuration**
- [ ] **Step 3: Update `README.md` with admin dashboard and Slack OAuth docs**

---

### Task 8: Verification & Packaging

- [ ] **Step 1: Run complete test suite (`uv run pytest -v`)**
- [ ] **Step 2: Update Debian packaging with data directory**
- [ ] **Step 3: Tag & Release `v0.2.0`**
