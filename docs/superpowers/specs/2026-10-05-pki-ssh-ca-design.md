# Spoutin PKI & OpenBao SSH CA Specification

**Date:** 2026-10-05  
**Status:** Approved  
**Author:** Adam Black & AI Assistant  
**Topic:** Rebrand `wifi-enrollment` to `pki` and add OpenBao-backed OpenSSH Certificate Authority  

---

## 1. Context & Purpose
The `spoutin-pki` platform currently manages 802.1X Wi-Fi device enrollment (X.509 EAP-TLS) with Slack approvals, OpenBao PKI backend, FreeRADIUS dynamic VLANs, and OPNsense CRL synchronization.

This project broadens the platform into a unified certificate management system named **PKI**. It introduces OpenSSH Certificate Authority functionality backed by OpenBao's native SSH secrets engine (`/v1/ssh`), implementing Meta's signed-certificate architecture ("Scalable and secure access with SSH"). It also carries out a clean, cold-turkey packaging and systemd migration from `wifi-enrollment` to `pki`.

---

## 2. Identity & Principals Model

OpenSSH certificates embed a **Key ID** (acting as the CN/identity) and a set of **Principals** (valid Unix accounts on target hosts).

| Entity / Persona | Key ID (CN) | Allowed Principals | Default Validity | Max Validity | Target Accounts |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Admin (`ablack`)** | `ablack` | `ablack`, `root`, `operator` | 8 Years (`70080h`) | 10 Years | `ablack` (personal), `root` (system admin), `operator` (generic) |
| **PKI Service Account** | `pki.int.spoutin.org` | `root`, `operator` | 10 Years (`87600h`) | 10 Years | Automated backups, cluster tasks, and host orchestration |
| **Generic / Guest User** | Requester Name (e.g. `john`) | `operator` | 8 Years (or custom) | 8 Years | `operator` (unprivileged role account across fleet) |

Target hosts across the fleet (`pve1`, `docker`, `opnsense`, `truenas`, etc.) only need one file: `/etc/ssh/ca.pub` (the OpenBao SSH CA public key) and `TrustedUserCAKeys /etc/ssh/ca.pub` in `/etc/ssh/sshd_config`.

---

## 3. Architecture & Interfaces

### 3.1 OpenBao Secrets Engine Configuration
* **Mount point**: `/v1/ssh` (type `ssh`).
* **CA Generation**: Native `ed25519` key generated inside OpenBao with 10-year validity (`87600h`).
* **CA Public Key**: Fetched via `GET /v1/ssh/config/ca` and exposed publicly by the PKI portal at `GET /ssh-ca.pub`.
* **Roles**:
  - `admin-user`:
    - `key_type`: `ca`
    - `allowed_users`: `ablack,root,operator`
    - `allowed_extensions`: `permit-pty,permit-agent-forwarding,permit-port-forwarding,permit-user-rc,permit-X11-forwarding`
    - `default_user`: `ablack`
    - `default_ttl`: `70080h`
    - `max_ttl`: `87600h`
  - `operator-user`:
    - `key_type`: `ca`
    - `allowed_users`: `operator`
    - `allowed_extensions`: `permit-pty,permit-agent-forwarding,permit-port-forwarding,permit-user-rc`
    - `default_user`: `operator`
    - `default_ttl`: `70080h`
    - `max_ttl`: `70080h`
* **AppRole Policy (`pki-portal`)**:
  Extends existing Wi-Fi permissions with:
  ```hcl
  path "ssh/config/ca" {
    capabilities = ["read"]
  }
  path "ssh/sign/admin-user" {
    capabilities = ["create", "update"]
  }
  path "ssh/sign/operator-user" {
    capabilities = ["create", "update"]
  }
  ```

### 3.2 Database Schema (`inventory.db`)
Existing tables: `certificates` (X.509 Wi-Fi) and `requests` (Wi-Fi enrollment).  
New tables:
```sql
CREATE TABLE IF NOT EXISTS ssh_requests (
    request_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    username TEXT NOT NULL,
    device_name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL,
    principals TEXT NOT NULL,       -- comma-separated: "ablack,root,operator"
    requested_ttl TEXT NOT NULL,    -- e.g. "70080h"
    status TEXT NOT NULL,           -- "PENDING", "APPROVED", "REJECTED"
    created_at INTEGER NOT NULL,
    reviewed_at INTEGER,
    reviewed_by TEXT
);

CREATE TABLE IF NOT EXISTS ssh_certificates (
    serial_number TEXT PRIMARY KEY, -- OpenBao serial string
    key_id TEXT NOT NULL,           -- e.g. "ablack"
    principals TEXT NOT NULL,       -- comma-separated: "ablack,root,operator"
    public_key TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL,
    certificate TEXT NOT NULL,      -- OpenSSH signed certificate string
    valid_from INTEGER NOT NULL,
    valid_to INTEGER NOT NULL,
    status TEXT NOT NULL,           -- "ACTIVE", "REVOKED"
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
);
```

### 3.3 HTTP & API Routes
* `GET /`: Main landing page (tabs for Wi-Fi and SSH).
* `GET /ssh-ca.pub`: Publicly serves the OpenBao SSH CA public key for host provisioning.
* `POST /api/ssh/request`: Guest/user submission of SSH public key.
  - Body: `{"name": "...", "username": "...", "device_name": "...", "public_key": "..."}`
  - Returns: `{"request_id": "...", "status": "PENDING"}`
* `GET /api/ssh/status/{request_id}`: Polls request status. When approved, returns certificate and download instructions.
* `GET /api/admin/ssh/requests`: Lists pending SSH signing requests.
* `POST /api/admin/ssh/requests/{request_id}/approve`: Approves and signs certificate with OpenBao.
  - Body: `{"principals": ["ablack", "root", "operator"], "ttl": "70080h"}`
* `POST /api/admin/ssh/requests/{request_id}/reject`: Rejects request.
* `POST /api/admin/ssh/quick-sign`: Admin-only direct signing form without request queue.
  - Body: `{"key_id": "ablack", "public_key": "...", "principals": ["ablack", "root", "operator"], "ttl": "70080h"}`
  - Returns: `{"certificate": "...", "serial_number": "...", "valid_to": ...}`
* `GET /api/admin/ssh/certificates`: Lists all signed SSH certificates.
* `POST /api/admin/ssh/certificates/{serial}/revoke`: Marks certificate as revoked in database and logs event.

### 3.4 Slack Integration
* Notification posted to Slack channel when a new SSH signing request arrives.
* Interactive Block Kit with **Approve** and **Reject** buttons.
* Approving via Slack uses default principals (`ablack,root,operator` for ablack; `operator` for others) and default 8-year TTL, and updates the Slack message with confirmation.

---

## 4. Cold-Turkey Packaging & Systemd Migration
* Package: `pki_<version>_amd64.deb`
* Replaces / Conflicts: `wifi-enrollment` (<< 0.3.0)
* Systemd Unit: `/lib/systemd/system/pki.service`
  - Explicitly stops and disables `wifi-enrollment.service` during preinst.
  - Removes old unit file on upgrade.
  - Automatically migrates `/etc/wifi-enrollment/config.env` -> `/etc/pki/config.env`.
  - Automatically migrates `/opt/wifi-enrollment/data/inventory.db` -> `/opt/pki/data/inventory.db`.
  - No aliases or legacy symlinks.

---

## 5. Verification Plan
1. **Unit Tests**:
   - `test_openbao_ssh_client.py`: Mock OpenBao `/v1/ssh/config/ca` and `/v1/ssh/sign/admin-user`.
   - `test_database_ssh.py`: Validate `ssh_requests` and `ssh_certificates` CRUD.
   - `test_ssh_server.py`: Test public request submission, status polling, admin quick-sign, approval, and revocation.
2. **End-to-End Live Test**:
   - Generate test key: `ssh-keygen -t ed25519 -f ~/.ssh/id_test -C "test"`.
   - Sign via quick-sign on live service with principals `ablack,root,operator`.
   - Validate certificate fields with `ssh-keygen -Lf ~/.ssh/id_test-cert.pub`.
   - Verify `ssh-ca.pub` downloaded from `https://wifi.int.spoutin.org/ssh-ca.pub`.
