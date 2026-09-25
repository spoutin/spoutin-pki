# Deployment Guide: wifi-enrollment on step-ca LXC

This guide covers deploying the **wifi-enrollment** service and **Caddy** on your `step-ca` Proxmox LXC container.

---

## 1. Prepare Directory on step-ca LXC

SSH into your `step-ca` container:

```bash
# Clone or copy spoutin-pki to /opt/spoutin-pki
mkdir -p /opt/spoutin-pki
cd /opt/spoutin-pki

# Copy files or git clone
git clone <your-repo-url> /opt/spoutin-pki
```

---

## 2. Install Python Dependencies with `uv`

```bash
# Install uv if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.cargo/env

# Sync dependencies into local venv
cd /opt/spoutin-pki
uv sync
```

---

## 3. Configure Environment Variables

Create `/opt/spoutin-pki/.env`:

```bash
cp /opt/spoutin-pki/.env.example /opt/spoutin-pki/.env
chmod 600 /opt/spoutin-pki/.env
nano /opt/spoutin-pki/.env
```

Ensure the following variables are filled in:
* `OPNSENSE_URL=https://opnsense.int.spoutin.org`
* `OPNSENSE_API_KEY=<your-key>`
* `OPNSENSE_API_SECRET=<your-secret>`
* `SLACK_BOT_TOKEN=xoxb-...`
* `SLACK_APP_TOKEN=xapp-...`
* `SLACK_CHANNEL_ID=C0XXXXXXXXX`

---

## 4. Install & Start systemd Service

```bash
# Copy systemd unit file
cp /opt/spoutin-pki/infra/systemd/wifi-enrollment.service /etc/systemd/system/

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable --now wifi-enrollment

# Verify service is running
systemctl status wifi-enrollment
journalctl -u wifi-enrollment -n 50 --no-pager
```

---

## 5. Configure Caddy with Cloudflare DNS

1. Install Caddy with the Cloudflare DNS module:
   ```bash
   # Using xcaddy or downloading caddy with cloudflare plugin:
   curl -o /usr/bin/caddy "https://caddyserver.com/api/download?os=linux&arch=amd64&p=github.com%2Fcaddy-dns%2Fcloudflare"
   chmod +x /usr/bin/caddy
   ```

2. Set Cloudflare API Token in Caddy's environment (`/etc/systemd/system/caddy.service.d/override.conf`):
   ```ini
   [Service]
   Environment="CLOUDFLARE_API_TOKEN=your_cloudflare_api_token_here"
   ```

3. Deploy Caddyfile:
   ```bash
   mkdir -p /etc/caddy
   cp /opt/spoutin-pki/infra/caddy/Caddyfile /etc/caddy/Caddyfile
   systemctl daemon-reload
   systemctl restart caddy
   systemctl status caddy
   ```

---

## 6. Verification

1. On a client device, navigate to `https://wifi.int.spoutin.org`.
2. Confirm the browser displays a trusted Let's Encrypt certificate without warnings.
3. Submit a test request (e.g. `test-device`).
4. Check your Slack channel: verify the interactive card appears with the `8 - SemiPrivate` VLAN dropdown.
5. Click **`[ ⚡ Quick Approve (VLAN 8) ]`** or **`[ ✏️ Edit & Approve ]`**.
6. Verify the web page automatically downloads `test-device.p12` and displays your 4-digit PIN!
