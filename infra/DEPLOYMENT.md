# Deployment Guide: wifi-enrollment on Dedicated Ubuntu LXC

This guide covers deploying the **wifi-enrollment** service on a dedicated Ubuntu LXC container using **Infisical PKI** (`https://secrets.int.spoutin.org`) or legacy **step-ca**.

---

## 1. Prepare Directory on LXC

SSH into your container:

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
curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="/usr/local/bin" sh

# Sync dependencies into local venv
cd /opt/spoutin-pki
uv sync
```

---

## 3. Configure Environment Variables

Create `/etc/wifi-enrollment/config.env`:

```bash
mkdir -p /etc/wifi-enrollment
cp /opt/spoutin-pki/config.env.example /etc/wifi-enrollment/config.env
chmod 600 /etc/wifi-enrollment/config.env
nano /etc/wifi-enrollment/config.env
```

Ensure the following variables are filled in:
* `CA_PROVIDER=infisical`
* `INFISICAL_URL=https://secrets.int.spoutin.org`
* `INFISICAL_CLIENT_ID=<your-machine-identity-client-id>`
* `INFISICAL_CLIENT_SECRET=<your-machine-identity-client-secret>`
* `INFISICAL_PROJECT_ID=<your-project-id>`
* `INFISICAL_CA_ID=<your-ca-id>`
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
cp /opt/spoutin-pki/packaging/systemd/wifi-enrollment.service /etc/systemd/system/

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable --now wifi-enrollment

# Verify service is running
systemctl status wifi-enrollment
journalctl -u wifi-enrollment -n 50 --no-pager
```

---

## 5. Configure External Reverse Proxy (Caddy / Nginx)

Set up your reverse proxy on port 80/443 to proxy requests to `http://127.0.0.1:8000`.

### Caddy Example:
```caddyfile
wifi.int.spoutin.org {
    tls {
        dns cloudflare {env.CLOUDFLARE_API_TOKEN}
        resolvers 1.1.1.1 8.8.8.8
    }
    reverse_proxy 127.0.0.1:8000
}
```

---

## 6. Verification

1. On a client device, navigate to `https://wifi.int.spoutin.org`.
2. Submit a test request (e.g. `test-device`).
3. Check your Slack channel: verify the interactive card appears with the `8 - SemiPrivate` VLAN dropdown.
4. Click **`[ ⚡ Quick Approve (VLAN 8) ]`** or **`[ ✏️ Edit & Approve ]`**.
5. Verify the web page automatically downloads `test-device.p12` and displays your 4-digit PIN!
6. View the new certificate in your Infisical Certificate Manager dashboard under your Issuing CA.
