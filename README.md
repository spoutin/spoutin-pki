# spoutin-pki

Monorepo for Spoutin Home Network PKI automation and certificate management.

## Services & Components

* **`services/wifi-enrollment`**: Automated EAP-TLS client enrollment web portal backed by Slack Socket Mode approvals, `step-ca` REST API, and OPNsense FreeRADIUS.
* **`infra/step-ca`**: Smallstep CA configurations, templates (`eap-client.json`), and systemd units.
* **`infra/caddy`**: Reverse proxy configuration with Cloudflare DNS-01 Let's Encrypt TLS.
* **`infra/systemd`**: Service definitions for deployment on the `step-ca` LXC container.

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

This section details how to install and configure the **`wifi-enrollment`** service and its dependencies on your `step-ca` Proxmox LXC container.

### 1. Prerequisites

* **`step-ca`** running and configured with your Intermediate CA and 6-year claims (`52560h`).
* **OPNsense** with the `os-freeradius` plugin installed and EAP-TLS configured.
* **Slack Workspace** with administrative permissions to create a Slack App.
* **Cloudflare API Token** with DNS Zone edit permissions for Let's Encrypt DNS-01 challenges.

---

### 2. Slack App Setup (Socket Mode)

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
   * Click **Install to Workspace**.
   * Copy the Bot User OAuth Token starting with `xoxb-...` (this is `SLACK_BOT_TOKEN`).
5. In your Slack client:
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
5. Ensure the user has permissions for **Services: FreeRADIUS** (`api/freeradius/*`).

---

### 4. Installation via Debian Package (`.deb`) — Recommended

The GitHub Actions workflow builds a unified `.deb` package containing the custom Caddy binary (with Cloudflare DNS), `wifi-enrollment` service, systemd units, and boilerplate configs.

1. **Download the latest `.deb` package** from your repository's GitHub Releases (or GitHub Actions artifacts).
2. **Install on the `step-ca` LXC:**
   ```bash
   dpkg -i wifi-enrollment_0.1.0_amd64.deb
   ```
   *The package automatically sets up the `caddy` user, installs `uv`, creates `/opt/wifi-enrollment`, builds the virtualenv, and configures systemd.*

3. **Configure Environment (`/etc/wifi-enrollment/.env`):**
   ```bash
   nano /etc/wifi-enrollment/.env
   ```
   Fill in your `OPNSENSE_API_KEY`, `OPNSENSE_API_SECRET`, and `SLACK_*` tokens.

4. **Configure Cloudflare API Token for Caddy:**
   ```bash
   mkdir -p /etc/systemd/system/caddy.service.d
   cat << 'EOF' > /etc/systemd/system/caddy.service.d/override.conf
   [Service]
   Environment="CLOUDFLARE_API_TOKEN=your_cloudflare_api_token_here"
   EOF
   systemctl daemon-reload
   ```

5. **Start and Manage Services via Unified Target:**
   The package configures systemd dependencies so that `step-ca`, `wifi-enrollment`, and `caddy` start in their required order. You can manage the entire stack with the unified `spoutin-pki.target`:
   ```bash
   # Start the entire PKI stack (step-ca -> wifi-enrollment -> caddy)
   systemctl start spoutin-pki.target

   # Check status of the stack
   systemctl status spoutin-pki.target

   # Or manage individual services:
   systemctl status wifi-enrollment
   systemctl status caddy
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

# 4. Configure .env file
mkdir -p /etc/wifi-enrollment
cp .env.example /etc/wifi-enrollment/.env
chmod 600 /etc/wifi-enrollment/.env
ln -sf /etc/wifi-enrollment/.env .env
nano /etc/wifi-enrollment/.env
```

Ensure credentials are configured in `/etc/wifi-enrollment/.env`:

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

