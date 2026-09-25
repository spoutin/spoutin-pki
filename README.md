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
