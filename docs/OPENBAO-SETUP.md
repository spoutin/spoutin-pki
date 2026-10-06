# OpenBao PKI, Secret Injection & Wi-Fi Enrollment Setup Guide

This guide documents the end-to-end architecture and step-by-step configuration for:
1. **OpenBao Server**: KV Secret Engine, PKI CA hierarchy, AppRole service accounts.
2. **Caddy Host**: Native systemd monitoring with OpenBao Agent in-memory secret injection and auto-restart on token rotation.
3. **Wi-Fi Enrollment Portal**: Standalone service connecting to OpenBao PKI via AppRole.
4. **OPNsense FreeRADIUS**: CRL synchronization and EAP-TLS validation.

---

## Architecture Overview

```
                          +-------------------------------------------------------+
                          | OpenBao Server (secrets.int.spoutin.org:8200)         |
                          |  - KV v2 Engine: secret/caddy/cloudflare              |
                          |  - PKI Engine: /v1/pki (Intermediate CA)              |
                          |  - AppRoles: caddy-service & wifi-portal              |
                          +---------------------------+---------------------------+
                                                      |
                         +----------------------------+----------------------------+
                         | HTTPS / AppRole                                         | HTTPS / AppRole
                         v                                                         v
+-------------------------------------------------+     +-------------------------------------------------+
| Caddy Reverse Proxy                             |     | Wi-Fi Enrollment Portal                         |
|                                                 |     | (wifi.int.spoutin.org)                          |
| 1. openbao-agent.service                        |     |                                                 |
|    - Auto-auths via permanent AppRole           |     | - Package: wifi-enrollment.deb                  |
|    - Renders secret to RAM:                     |     | - Config: /etc/wifi-enrollment/config.env       |
|      /run/caddy/cloudflare.env                  |     | - Uses OpenBao AppRole                          |
|    - Auto-triggers: systemctl try-restart caddy |     | - In-memory key & CSR generation                |
|                                                 |     | - Signs certs via OpenBao /pki/sign/wifi-client |
| 2. caddy.service                                |     | - Distributes .p12 bundles with 4-digit PIN     |
|    - Type=notify (Direct systemd monitoring)    |     | - Proxies CRL at /crl.pem                       |
|    - Reads /run/caddy/cloudflare.env (RAM)      |     +------------------------+------------------------+
|    - Performs Cloudflare DNS-01 Let's Encrypt   |                              |
+-------------------------------------------------+                              | Syncs CRL / Pushes CRL
                                                                                 v
                                                        +-------------------------------------------------+
                                                        | OPNsense FreeRADIUS                             |
                                                        |  - Validates client certs via EAP-TLS           |
                                                        |  - sync-freeradius-crl.sh (cron via ETag)       |
                                                        |  - Real-time CRL push & restart on revocation   |
                                                        +-------------------------------------------------+
```

---

## Part 1: OpenBao Server Configuration

Run these commands on your OpenBao container using your root token:

```bash
export BAO_ADDR="https://127.0.0.1:8200"
export BAO_TOKEN="<your-root-token>"
export BAO_SKIP_VERIFY="true"
```

### 1. Enable AppRole Authentication
```bash
bao auth enable approle
```

---

### 2. Configure KV Secrets Engine & Cloudflare Secret for Caddy

```bash
# Enable KV v2 secrets engine
bao secrets enable -path=secret kv-v2

# Store your Cloudflare API token
bao kv put secret/caddy/cloudflare token="your_cloudflare_api_token_here"

# Create a read-only policy for Caddy
cat << 'EOF' > /tmp/caddy-policy.hcl
path "secret/data/caddy/*" {
  capabilities = ["read"]
}
EOF
bao policy write caddy-reader /tmp/caddy-policy.hcl
rm -f /tmp/caddy-policy.hcl

# Create AppRole for Caddy with non-expiring credentials
bao write auth/approle/role/caddy-service \
    token_policies="caddy-reader" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=0 \
    secret_id_num_uses=0

# Save the generated Role ID and Secret ID for Caddy
CADDY_ROLE_ID=$(bao read -field=role_id auth/approle/role/caddy-service/role-id)
CADDY_SECRET_ID=$(bao write -f -field=secret_id auth/approle/role/caddy-service/secret-id)

echo "Caddy Role ID:   $CADDY_ROLE_ID"
echo "Caddy Secret ID: $CADDY_SECRET_ID"
```

---

### 3. Configure PKI Secrets Engine for Wi-Fi Client Certificates

```bash
# Enable PKI secrets engine
bao secrets enable pki

# Tune lease duration to 6 years (52560h)
bao secrets tune -max-lease-ttl=52560h pki

# Import your existing Intermediate CA bundle (private key + intermediate cert + root cert)
cat /tmp/intermediate_ca_key.pem \
    /etc/step-ca/certs/intermediate_ca.crt \
    /etc/step-ca/certs/root_ca.crt > /tmp/ca-bundle.pem

bao write pki/config/ca pem_bundle=@/tmp/ca-bundle.pem
rm -f /tmp/ca-bundle.pem

# Configure PKI URLs
bao write pki/config/urls \
    issuing_certificates="https://secrets.int.spoutin.org:8200/v1/pki/ca" \
    crl_distribution_points="https://wifi.int.spoutin.org/crl.pem"

# Create the Wi-Fi client role (allows plain device names as CN)
bao write pki/roles/wifi-client \
    allow_any_name=true \
    enforce_hostnames=false \
    client_flag=true \
    server_flag=false \
    key_type=rsa \
    key_bits=2048 \
    max_ttl=52560h \
    ttl=52560h \
    key_usage="DigitalSignature,KeyEncipherment" \
    ext_key_usage="ClientAuth"
```

---

### 4. Create AppRole for the Wi-Fi Enrollment Portal

```bash
# Create policy for Wi-Fi Portal
cat << 'EOF' > /tmp/wifi-portal-policy.hcl
path "pki/sign/wifi-client" {
  capabilities = ["create", "update"]
}
path "pki/revoke" {
  capabilities = ["create", "update"]
}
path "pki/crl" {
  capabilities = ["read"]
}
path "pki/crl/pem" {
  capabilities = ["read"]
}
path "pki/ca/pem" {
  capabilities = ["read"]
}
EOF
bao policy write wifi-portal /tmp/wifi-portal-policy.hcl
rm -f /tmp/wifi-portal-policy.hcl

# Create AppRole for Wi-Fi Portal with non-expiring credentials
bao write auth/approle/role/wifi-portal \
    token_policies="wifi-portal" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=0 \
    secret_id_num_uses=0

# Save the generated credentials
PORTAL_ROLE_ID=$(bao read -field=role_id auth/approle/role/wifi-portal/role-id)
PORTAL_SECRET_ID=$(bao write -f -field=secret_id auth/approle/role/wifi-portal/secret-id)

echo "Portal Role ID:   $PORTAL_ROLE_ID"
echo "Portal Secret ID: $PORTAL_SECRET_ID"
```

---

### 5. Configure OpenSSH Certificate Authority (SSH Secrets Engine)

OpenBao supports native OpenSSH certificate signing. Target hosts (`pve1`, `docker`, `opnsense`, etc.) only need to trust the CA's public key via `TrustedUserCAKeys`.

```bash
# 1. Enable SSH secrets engine at /v1/ssh
bao secrets enable -path=ssh ssh
bao secrets tune -max-lease-ttl=87600h ssh

# 2. Generate native ED25519 SSH CA key (10-year validity)
bao write ssh/config/ca generate_signing_key=true key_type=ed25519

# 3. Configure admin-user role (defaults to ablack, allows root and operator)
bao write ssh/roles/admin-user \
    key_type=ca \
    allow_user_certificates=true \
    allowed_users="ablack,root,operator" \
    allowed_extensions="permit-pty,permit-agent-forwarding,permit-port-forwarding,permit-user-rc,permit-X11-forwarding" \
    default_user="ablack" \
    default_ttl="70080h" \
    max_ttl="87600h"

# 4. Configure operator-user role (standard generic operational account)
bao write ssh/roles/operator-user \
    key_type=ca \
    allow_user_certificates=true \
    allowed_users="operator" \
    allowed_extensions="permit-pty,permit-agent-forwarding,permit-port-forwarding,permit-user-rc" \
    default_user="operator" \
    default_ttl="70080h" \
    max_ttl="70080h"

# 5. Update wifi-portal policy to include SSH CA permissions
cat << 'EOF' > /tmp/wifi-portal-policy.hcl
path "pki/sign/wifi-client" {
  capabilities = ["create", "update"]
}
path "pki/revoke" {
  capabilities = ["create", "update"]
}
path "pki/crl" {
  capabilities = ["read"]
}
path "pki/crl/pem" {
  capabilities = ["read"]
}
path "pki/ca/pem" {
  capabilities = ["read"]
}

# SSH CA Engine
path "ssh/config/ca" {
  capabilities = ["read"]
}
path "ssh/sign/admin-user" {
  capabilities = ["create", "update"]
}
path "ssh/sign/operator-user" {
  capabilities = ["create", "update"]
}
EOF
bao policy write wifi-portal /tmp/wifi-portal-policy.hcl
rm -f /tmp/wifi-portal-policy.hcl
```

---

## Part 2: Caddy Host Configuration (Secret Injection & Monitoring)

On the host running Caddy:

### 1. Store Caddy AppRole Credentials
```bash
mkdir -p /etc/openbao
chmod 700 /etc/openbao

echo "$CADDY_ROLE_ID" > /etc/openbao/caddy_role_id
echo "$CADDY_SECRET_ID" > /etc/openbao/caddy_secret_id
chmod 600 /etc/openbao/caddy_*
```

---

### 2. Configure OpenBao Agent (`/etc/openbao/agent-caddy.hcl`)

```hcl
# /etc/openbao/agent-caddy.hcl

# Check for KV updates every 1 minute
template_config {
  static_secret_render_interval = "1m"
}

# Auto-authenticate via AppRole
auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path                   = "/etc/openbao/caddy_role_id"
      secret_id_file_path                 = "/etc/openbao/caddy_secret_id"
      remove_secret_id_file_after_reading = false
    }
  }
}

# Render Cloudflare token to RAM and restart Caddy on token rotation
template {
  destination = "/run/caddy/cloudflare.env"
  perms       = "0600"
  contents    = <<EOF
CLOUDFLARE_API_TOKEN={{ with secret "secret/data/caddy/cloudflare" }}{{ .Data.data.token }}{{ end }}
EOF

  exec {
    command = ["systemctl", "try-restart", "caddy"]
  }
}
```

---

### 3. OpenBao Agent Service (`/etc/systemd/system/openbao-agent.service`)

```ini
[Unit]
Description=OpenBao Agent for Caddy Secret Injection
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Environment="BAO_ADDR=https://127.0.0.1:8200"
Environment="BAO_SKIP_VERIFY=true"
RuntimeDirectory=caddy
RuntimeDirectoryMode=0755
ExecStart=/usr/bin/bao agent -config=/etc/openbao/agent-caddy.hcl
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

---

### 4. Native Caddy Service (`/etc/systemd/system/caddy.service`)

```ini
[Unit]
Description=Caddy Web Server
Documentation=https://caddyserver.com/docs/
After=network.target network-online.target openbao-agent.service
Wants=network-online.target
Requires=openbao-agent.service

[Service]
Type=notify
User=root
EnvironmentFile=/run/caddy/cloudflare.env
ExecStart=/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/bin/caddy reload --config /etc/caddy/Caddyfile --force
TimeoutStopSec=5s
LimitNOFILE=1048576
Restart=on-failure
RestartSec=3s
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

#### Optional Systemd Drop-In Override (`/etc/systemd/system/caddy.service.d/override.conf`)
```ini
[Service]
Environment=BAO_ADDR="https://127.0.0.1:8200"
Environment=BAO_SKIP_VERIFY="true"
```

---

### 5. Caddyfile Configuration (`/etc/caddy/Caddyfile`)

```caddyfile
# Reusable TLS and Security Header Snippets
(cloudflare_tls) {
    tls {
        dns cloudflare "{$CLOUDFLARE_API_TOKEN}"
        resolvers 1.1.1.1 8.8.8.8
    }
}

(security_headers) {
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        X-XSS-Protection "1; mode=block"
        Referrer-Policy "strict-origin-when-cross-origin"
    }
}

# 1. UniFi Captive Portal
captive-portal.int.spoutin.org {
    import cloudflare_tls
    import security_headers
    encode gzip zstd

    reverse_proxy 127.0.0.1:3000 {
        header_up Host {upstream_hostport}
    }
}

# 2. Spoutin Wi-Fi Enrollment Portal & Admin Dashboard
wifi.int.spoutin.org {
    import cloudflare_tls
    import security_headers

    reverse_proxy 127.0.0.1:8000 {
        flush_interval -1
        header_up Host {host}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
}

# 3. OpenBao Secrets Management & PKI Portal
secrets.int.spoutin.org {
    import cloudflare_tls

    # Restrict OpenBao from Guest Wi-Fi subnets
    @untrusted {
        client_ip 192.168.111.0/24 10.0.1.0/24
    }
    abort @untrusted

    reverse_proxy https://127.0.0.1:8200 {
        header_up Host {host}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
        transport http {
            tls_insecure_skip_verify
        }
    }
}
```

---

### 6. Enable & Start Services

```bash
systemctl daemon-reload
systemctl enable openbao-agent caddy
systemctl start openbao-agent
systemctl start caddy

# Verify both are green and running
systemctl status openbao-agent
systemctl status caddy
```

---

## Part 3: Wi-Fi Enrollment Portal Configuration

On your dedicated `wifi-enrollment` container:

### 1. Install Debian Package
```bash
wget https://github.com/spoutin/spoutin-pki/releases/download/v0.2.22-beta.3/wifi-enrollment_0.2.22-beta.3_amd64.deb
apt install -y ./wifi-enrollment_0.2.22-beta.3_amd64.deb
```

---

### 2. Configure `/etc/wifi-enrollment/config.env`

```ini
# /etc/wifi-enrollment/config.env

# --- Service & Network Settings ---
SERVICE_HOST=127.0.0.1
SERVICE_PORT=8000
NETWORK_DOMAIN=int.spoutin.org
RADIUS_SERVER_DOMAIN=radius.int.spoutin.org
LOG_LEVEL=INFO

# --- Rate Limiting & TTL ---
RATE_LIMIT_REQUESTS=3
RATE_LIMIT_WINDOW_SECONDS=600
REQUEST_TTL_SECONDS=900
MAX_PENDING_REQUESTS=10

# --- Certificate Authority Provider ---
CA_PROVIDER=openbao

# --- OpenBao PKI (AppRole Service Account) ---
OPENBAO_URL=https://secrets.int.spoutin.org:8200
OPENBAO_ROLE_ID=<paste-PORTAL_ROLE_ID>
OPENBAO_SECRET_ID=<paste-PORTAL_SECRET_ID>
OPENBAO_PKI_MOUNT=pki
OPENBAO_ROLE=wifi-client
OPENBAO_VERIFY_SSL=true
CERT_VALIDITY_HOURS=52560h

# --- OPNsense FreeRADIUS API ---
OPNSENSE_URL=https://opnsense.int.spoutin.org
OPNSENSE_API_KEY=your_opnsense_api_key
OPNSENSE_API_SECRET=your_opnsense_api_secret
OPNSENSE_VERIFY_SSL=false
OPNSENSE_INTERMEDIATE_CA_REFID=

# --- Slack App (Socket Mode & Admin OAuth) ---
SLACK_BOT_TOKEN=xoxb-...
SLACK_APP_TOKEN=xapp-...
SLACK_CHANNEL_ID=C0XXXXXXXXX
SLACK_CLIENT_ID=your_slack_client_id
SLACK_CLIENT_SECRET=your_slack_client_secret
ADMIN_SLACK_EMAILS=adam@spoutin.org
SESSION_SECRET_KEY=change-this-to-any-random-string
DATABASE_PATH=/opt/wifi-enrollment/data/inventory.db
```

---

### 3. Start the Portal
```bash
systemctl restart wifi-enrollment
systemctl status wifi-enrollment
```

---

## Part 4: OPNsense FreeRADIUS CRL Synchronization

The FreeRADIUS sync script runs periodically via cron on OPNsense to ensure CRL updates are checked with zero disk writes if unchanged (HTTP 304).

### 1. Test the Script Manually on OPNsense:
```bash
/usr/local/bin/sync-freeradius-crl.sh
```

### 2. Automated Cron Setup:
Under **System &rarr; Configuration &rarr; Cron** in OPNsense:
- **Minutes**: `*/15` (every 15 minutes)
- **Command**: `/usr/local/bin/sync-freeradius-crl.sh`
- **Description**: `Sync Spoutin Wi-Fi CRL`

---

## Verification & Health Check Checklist

- [ ] **Secret Injection**: `/run/caddy/cloudflare.env` exists in RAM and contains `CLOUDFLARE_API_TOKEN`.
- [ ] **Caddy Monitoring**: `systemctl status caddy` reports `active (running)` with `Type=notify`.
- [ ] **Token Rotation**: Running `bao kv put secret/caddy/cloudflare token="..."` automatically updates `/run/caddy/cloudflare.env` and restarts Caddy within 1 minute.
- [ ] **Client Enrollment**: Submit a test request at `https://wifi.int.spoutin.org`, approve it in Slack, and confirm `.p12` bundle downloads with a 4-digit PIN.
- [ ] **Revocation**: Revoke a test certificate in `/admin` &rarr; confirm it appears in OpenBao's CRL and is pushed to OPNsense FreeRADIUS.
