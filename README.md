# spoutin-pki

Monorepo for Spoutin Home Network PKI automation and certificate management.

## Services & Components

* **`services/wifi-enrollment`**: Automated EAP-TLS client enrollment web portal backed by Slack Socket Mode approvals, Infisical / `step-ca` PKI REST APIs, and OPNsense FreeRADIUS.
* **`infra/step-ca`**: Smallstep CA configurations, templates (`eap-client.json`), and systemd units (legacy/optional).
* **`infra/caddy`**: Reverse proxy configuration example with Cloudflare DNS-01 Let's Encrypt TLS.
* **`scripts/sync-freeradius-crl.sh`**: Zero-touch FreeRADIUS CRL synchronization script for OPNsense.

## Quickstart

```bash
# Install dependencies
uv sync

# Run tests
uv run pytest -v

# Run local development server
just dev
```

## Installation & Configuration

This section details how to install and configure the **`wifi-enrollment`** service on a dedicated Ubuntu/Debian LXC container.

### 1. Prerequisites

* **Infisical** (e.g. self-hosted `https://secrets.int.spoutin.org` or Cloud) with an active Certificate Authority (CA) and Universal Auth Machine Identity. *(Or legacy `step-ca`).*
* **OPNsense** with the `os-freeradius` plugin installed and EAP-TLS configured.
* **Slack Workspace** with administrative permissions to create a Slack App.
* **Reverse Proxy (Optional)**: Caddy, Nginx, or HAProxy pointing to `http://127.0.0.1:8000`.

---

### 2. Slack App Setup (Socket Mode & Admin OAuth)

1. Navigate to [api.slack.com/apps](https://api.slack.com/apps) and click **Create New App** → **From scratch**. Name it `WiFi Enrollment Bot`.
2. Under **Settings → Socket Mode**:
   * Toggle **Enable Socket Mode** to `ON`.
   * When prompted, create an App-Level Token named `socket-token` with the **`connections:write`** scope.
   * Copy the token starting with `xapp-...` (this is `SLACK_APP_TOKEN`).
3. Under **Features → Interactivity & Shortcuts**:
   * Toggle **Interactivity** to `ON` (Socket Mode routes button clicks and modals automatically; no Request URL needed).
4. Under **Features → OAuth & Permissions**:
   * Add the following **Bot Token Scopes**:
     * `chat:write` (to post and update interactive approval cards)
   * Under **User Token Scopes** (for Admin Web Dashboard login):
     * `openid`, `email`, `profile`
   * Under **Redirect URLs**:
     * Click **Add New Redirect URL** and enter:
       ```text
       https://wifi.int.spoutin.org/admin/auth/callback
       ```
     * Click **Add**, then click **Save URLs**.
     * ⚠️ **CRITICAL:** You *must* click the green **Save URLs** button after adding the URL! If you navigate away without clicking **Save URLs**, Slack discards the URL and dashboard logins will fail with `redirect_uri did not match any configured URIs`.
   * Click **Install to Workspace** (or **Reinstall to Workspace** at the top of the page).
   * Copy the Bot User OAuth Token starting with `xoxb-...` (this is `SLACK_BOT_TOKEN`).
5. Under **Settings → Basic Information**:
   * Scroll to the **App Credentials** section.
   * Copy the **Client ID** (this is `SLACK_CLIENT_ID`).
   * Click **Show** and copy the **Client Secret** (this is `SLACK_CLIENT_SECRET`).
6. In your Slack client:
   * Create or open your private admin notifications channel (e.g., `#wifi-approvals`).
   * Invite the bot: `/invite @WiFi Enrollment Bot`.
   * Copy the **Channel ID** (Right-click channel name → View channel details → Channel ID at the bottom; e.g., `C0123456789`). This is `SLACK_CHANNEL_ID`.

---

### 3. OPNsense FreeRADIUS API Setup

1. In OPNsense, go to **System → Access → Users**.
2. Select your admin user (or create a dedicated `api-service` user).
3. Under **API keys**, click the **+** icon to generate an API key.
4. A `.key` file downloads containing:
   * Key (`OPNSENSE_API_KEY`)
   * Secret (`OPNSENSE_API_SECRET`)
5. Ensure the user has permissions for **Services: FreeRADIUS** (`api/freeradius/*`) and **System: Trust** (`api/trust/*`).

---

### 4. Installation via Debian Package (`.deb`) — Recommended

The GitHub Actions workflow builds a clean, lightweight `.deb` package containing the `wifi-enrollment` service and systemd daemonization. Reverse proxies (like Caddy) are kept external and managed separately.

1. **Download the latest `.deb` package** from your repository's [GitHub Releases](https://github.com/spoutin/spoutin-pki/releases).
2. **Install on your LXC container:**
   ```bash
   apt install ./wifi-enrollment_0.2.22_amd64.deb
   ```
   *The package installs `uv`, copies `/opt/wifi-enrollment`, builds the virtualenv, creates `/opt/wifi-enrollment/data` for the SQLite certificate inventory, and enables systemd.*

3. **Configure Environment (`/etc/wifi-enrollment/config.env`):**
   ```bash
   nano /etc/wifi-enrollment/config.env
   ```
   Fill in your Infisical, Slack, and OPNsense settings:
   ```ini
   CA_PROVIDER=infisical

   # Infisical Machine Identity
   INFISICAL_URL=https://secrets.int.spoutin.org
   INFISICAL_CLIENT_ID=your_client_id
   INFISICAL_CLIENT_SECRET=your_client_secret
   INFISICAL_PROJECT_ID=your_project_id
   INFISICAL_CA_ID=your_ca_id

   # Slack OAuth & Admin Web Portal
   SLACK_BOT_TOKEN=xoxb-...
   SLACK_APP_TOKEN=xapp-...
   SLACK_CHANNEL_ID=C0XXXXXXXXX
   SLACK_CLIENT_ID=your_slack_client_id
   SLACK_CLIENT_SECRET=your_slack_client_secret
   ADMIN_SLACK_EMAILS=adam@spoutin.org
   SESSION_SECRET_KEY=change-this-to-any-random-string

   # OPNsense FreeRADIUS
   OPNSENSE_URL=https://opnsense.int.spoutin.org
   OPNSENSE_API_KEY=your_key
   OPNSENSE_API_SECRET=your_secret
   ```

4. **Start the Service:**
   ```bash
   systemctl start wifi-enrollment
   systemctl status wifi-enrollment
   ```

5. **(Optional) Configure External Caddy Reverse Proxy:**
   If you use Caddy for SSL termination and Cloudflare DNS:
   ```caddyfile
   # /etc/caddy/Caddyfile
   wifi.int.spoutin.org {
       tls {
           dns cloudflare {env.CLOUDFLARE_API_TOKEN}
           resolvers 1.1.1.1 8.8.8.8
       }
       reverse_proxy 127.0.0.1:8000
   }
   ```

---

### 5. Alternative: Manual Deployment from Git

If you prefer deploying directly from the git repository without the `.deb` package:

```bash
# 1. Clone repository to /opt/spoutin-pki
mkdir -p /opt/spoutin-pki
git clone <your-repo-url> /opt/spoutin-pki
cd /opt/spoutin-pki

# 2. Install uv package manager
curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="/usr/local/bin" sh

# 3. Install Python dependencies
uv sync

# 4. Configure config.env file
mkdir -p /etc/wifi-enrollment
cp config.env.example /etc/wifi-enrollment/config.env
chmod 600 /etc/wifi-enrollment/config.env
ln -sf /etc/wifi-enrollment/config.env config.env
nano /etc/wifi-enrollment/config.env
```

Ensure credentials are configured in `/etc/wifi-enrollment/config.env`:

```ini
SERVICE_HOST=127.0.0.1
SERVICE_PORT=8000
NETWORK_DOMAIN=int.spoutin.org
RADIUS_SERVER_DOMAIN=radius.int.spoutin.org

# step-ca paths
STEP_CA_URL=https://127.0.0.1:9000
STEP_CA_PROVISIONER_NAME=admin@int.spoutin.org
STEP_ROOT_CERT_PATH=/etc/step-ca/certs/root_ca.crt
STEP_INTERMEDIATE_CERT_PATH=/etc/step-ca/certs/intermediate_ca.crt

# OPNsense FreeRADIUS API
OPNSENSE_URL=https://opnsense.int.spoutin.org
OPNSENSE_API_KEY=your_opnsense_api_key
OPNSENSE_API_SECRET=your_opnsense_api_secret
OPNSENSE_VERIFY_SSL=false

# Slack Socket Mode
SLACK_BOT_TOKEN=xoxb-...
SLACK_APP_TOKEN=xapp-...
SLACK_CHANNEL_ID=C0XXXXXXXXX

# Slack OAuth & Admin Web Portal
SLACK_CLIENT_ID=1234567890.9876543210
SLACK_CLIENT_SECRET=your_slack_client_secret
ADMIN_SLACK_EMAILS=adam@spoutin.org,admin@spoutin.org
SESSION_SECRET_KEY=change-this-to-a-random-secret
DATABASE_PATH=/opt/wifi-enrollment/data/inventory.db
```

Install the systemd service units and target:

```bash
cp /opt/spoutin-pki/packaging/systemd/wifi-enrollment.service /etc/systemd/system/
cp /opt/spoutin-pki/packaging/systemd/spoutin-pki.target /etc/systemd/system/
systemctl daemon-reload
systemctl enable wifi-enrollment.service spoutin-pki.target
systemctl start spoutin-pki.target

# Verify status
systemctl status wifi-enrollment
journalctl -u wifi-enrollment -n 50 --no-pager
```

---

### 6. Configuring Caddy Reverse Proxy (Manual Install)

If manually deploying Caddy without the `.deb`:

1. **Install official Caddy package:**
   * **On Debian / Ubuntu:**
     ```bash
     apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
     curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
     curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
     apt update
     apt install -y caddy
     ```
   * **On Alpine Linux:**
     ```bash
     apk add caddy
     ```

2. **Replace `/usr/bin/caddy` with the Cloudflare DNS plugin build:**
   ```bash
   systemctl stop caddy
   curl -o /usr/bin/caddy "https://caddyserver.com/api/download?os=linux&arch=amd64&p=github.com%2Fcaddy-dns%2Fcloudflare"
   chmod +x /usr/bin/caddy

   # Verify the module is included
   caddy list-modules | grep cloudflare
   # Output: dns.providers.cloudflare
   ```

3. **Configure Cloudflare API token in systemd override:**
   ```bash
   mkdir -p /etc/systemd/system/caddy.service.d
   cat << 'EOF' > /etc/systemd/system/caddy.service.d/override.conf
   [Service]
   Environment="CLOUDFLARE_API_TOKEN=your_cloudflare_token_here"
   EOF
   ```

4. **Deploy Caddyfile & Unit Files:**
   ```bash
   mkdir -p /etc/caddy
   cp /opt/spoutin-pki/infra/caddy/Caddyfile /etc/caddy/Caddyfile
   cp /opt/spoutin-pki/packaging/systemd/caddy.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable caddy
   systemctl restart caddy
   systemctl status caddy
   ```

---

### 7. Verifying End-to-End Enrollment

1. On a client device connected to your Guest or Setup Wi-Fi, open `https://wifi.int.spoutin.org`.
2. Enter a device name (e.g. `ablack-phone`) and select your platform (e.g. Android).
3. Click **Request Wi-Fi Access**.
4. In Slack, inspect the incoming card:
   * Verify the requested name, IP, and VLAN options (`8 - SemiPrivate (Default)`, `1 - LAN`, `2 - DMS`, `9 - IoT`).
   * Test **`[ ⚡ Quick Approve (VLAN 8) ]`** or click **`[ ✏️ Edit & Approve ]`** to change the name/VLAN.
5. In your browser:
   * Verify the page transitions to approved and automatically downloads `ablack-phone.p12`.
   * Note the **4-digit PIN** displayed on screen.
6. In OPNsense:
   * Check **Services → FreeRADIUS → Users** and verify `ablack-phone` is registered with the selected VLAN.
7. Import the `.p12` bundle on the device and connect to your 802.1X SSID.

---

### 8. Admin Command Center & Certificate Revocation

The web portal includes an administrative command center at `https://wifi.int.spoutin.org/admin`.

#### Access & Authentication
1. Navigate to `https://wifi.int.spoutin.org/admin`. Unauthenticated requests redirect to `/admin/login`.
2. Click **Sign in with Slack**.
3. Upon completing OAuth with Slack, the service verifies that your Slack email address is listed in `ADMIN_SLACK_EMAILS` (comma-separated list in `.env`).
4. An encrypted, HttpOnly 24-hour session cookie (`wifi_admin_session`) is issued. Unauthorized Slack users receive a `403 Forbidden` screen.

#### Live Request Approvals with Slack Synchronization
* **Live Polling:** The dashboard displays pending enrollment requests in real time (refreshed every 5 seconds).
* **Action Buttons:** Administrators can click:
  * **`[ ⚡ Quick (VLAN 8) ]`**: Immediately approves the request for VLAN 8.
  * **`[ ✏️ Edit ]`**: Opens a modal to customize the device name or select an alternate VLAN (LAN, DMS, SemiPrivate, IoT).
  * **`[ ❌ Reject ]`**: Rejects the pending request.
* **Bi-Directional Slack Sync:** Approving or rejecting a request from the web dashboard automatically finds the corresponding Slack notification card in your `#wifi-approvals` channel and updates it in-place (e.g., `✅ Approved by @admin via Web Dashboard`).

#### Certificate Inventory & Real-Time Filtering
* Displays all active and revoked certificates recorded in the SQLite inventory (`data/inventory.db`).
* Displays Device Name, Platform, Assigned VLAN, Client IP, Serial Number, Issued Date, and Expiration Date.
* Filter certificates instantly using the search input, Status filter (`All`, `Active`, `Revoked`), or VLAN filter.

#### Two-Option Revocation Workflow
Click the red **Revoke** button next to any active certificate to open the revocation modal with two distinct options:

1. **`Revoke Certificate Only (CRL)`**:
   * Generates an ES256 revocation token and invokes `step-ca` (`POST /1.0/revoke`).
   * The certificate serial is immediately added to the Certificate Revocation List (CRL).
   * The user account in OPNsense FreeRADIUS is left intact.
2. **`Revoke Certificate & Delete FreeRADIUS User`**:
   * Revokes the certificate in `step-ca` (adding it to the CRL).
   * Queries the OPNsense FreeRADIUS API for the user's UUID and executes `POST /api/freeradius/user/delUser/{uuid}`.
   * Reloads the FreeRADIUS service (`POST /api/freeradius/service/reconfigure`) so the user can no longer authenticate under any credentials.

*(Note: Per design, revocations update the database and dashboard silently without posting noisy alerts to Slack).*

#### Public CRL Distribution & FreeRADIUS Synchronization
The service and reverse proxy expose the `step-ca` CRL publicly on your internal domain with HTTP `ETag` and `304 Not Modified` conditional request support:
* **`https://wifi.int.spoutin.org/crl.pem`** (PEM format, with ETag caching)
* **`https://wifi.int.spoutin.org/crl`** (DER / raw format)

To inspect the CRL or view revoked serial numbers:
```bash
curl -s https://wifi.int.spoutin.org/crl.pem | openssl crl -text -noout
```

##### Automated OPNsense FreeRADIUS Sync (Zero-Touch Setup)
To enable automatic, zero-disk-wear CRL synchronization on your OPNsense firewall:

1. **Deploy the Script on OPNsense:**
   SSH into your OPNsense firewall and download the synchronization script:
   ```bash
   curl -sSL -o /usr/local/bin/sync-wifi-crl.sh https://raw.githubusercontent.com/spoutin/spoutin-pki/main/scripts/sync-freeradius-crl.sh
   chmod +x /usr/local/bin/sync-wifi-crl.sh
   ```

2. **Add a Cron Job in OPNsense GUI:**
   * Go to **System → Settings → Cron**.
   * Click **`+`** to add a new cron job:
     * **Minutes:** `*/5` (runs every 5 minutes)
     * **Hours / Days / Months / Weekdays:** `*`
     * **Command:** `/usr/local/bin/sync-wifi-crl.sh`
     * **Description:** `Sync Wi-Fi CRL from Step-CA`
   * Click **Save** and **Apply changes**.

3. **Self-Initialization on First Run:**
   * The script automatically detects whether FreeRADIUS CRL checking is active (`check_crl = yes`).
   * On its first run, it automatically imports the CRL into OPNsense's Trust Store (**System → Trust → Revocation**), wires it into **Services → FreeRADIUS → EAP**, and reloads the service—requiring **zero manual GUI clicks**.
   * On subsequent runs, it uses HTTP `ETag` and `304 Not Modified` in RAM (`/tmp`). FreeRADIUS is only reloaded when a certificate is actually revoked.

