import os
from pydantic_settings import BaseSettings, SettingsConfigDict


def _resolve_env_files() -> tuple[str, ...]:
    custom = os.getenv("CONFIG_PATH", "").strip()
    candidates = [
        ".env",
        "config.env",
        "/etc/pki/config.env",
        "/etc/wifi-enrollment/config.env",
    ]
    if custom:
        candidates.append(custom)
    return tuple(candidates)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_resolve_env_files(),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Web Service
    SERVICE_HOST: str = "127.0.0.1"
    SERVICE_PORT: int = 8000
    NETWORK_DOMAIN: str = "int.spoutin.org"
    RADIUS_SERVER_DOMAIN: str = "radius.int.spoutin.org"
    LOG_LEVEL: str = "INFO"

    # Rate Limiting & TTL
    RATE_LIMIT_REQUESTS: int = 3
    RATE_LIMIT_WINDOW_SECONDS: int = 600  # 10 minutes
    REQUEST_TTL_SECONDS: int = 900       # 15 minutes
    MAX_PENDING_REQUESTS: int = 10

    # CA Provider ("openbao", "infisical", or "step-ca")
    CA_PROVIDER: str = "openbao"

    # OpenBao / Vault PKI & SSH API (AppRole or static token)
    OPENBAO_URL: str = "http://127.0.0.1:8200"
    OPENBAO_ROLE_ID: str = ""
    OPENBAO_SECRET_ID: str = ""
    OPENBAO_TOKEN: str = ""
    OPENBAO_PKI_MOUNT: str = "pki"
    OPENBAO_ROLE: str = "wifi-client"
    OPENBAO_SSH_MOUNT: str = "ssh"
    OPENBAO_SSH_ADMIN_ROLE: str = "admin-user"
    OPENBAO_SSH_OPERATOR_ROLE: str = "operator-user"
    OPENBAO_VERIFY_SSL: bool = True

    # Infisical PKI API (Self-Hosted or Cloud)
    INFISICAL_URL: str = "https://secrets.int.spoutin.org"
    INFISICAL_CLIENT_ID: str = ""
    INFISICAL_CLIENT_SECRET: str = ""
    INFISICAL_PROJECT_ID: str = ""
    INFISICAL_CA_ID: str = ""
    INFISICAL_VERIFY_SSL: bool = True

    # step-ca REST API (legacy/fallback)
    STEP_CA_URL: str = "https://127.0.0.1:9000"
    STEP_CA_CONFIG_PATH: str = "/etc/step-ca/config/ca.json"
    STEP_CA_PROVISIONER_NAME: str = "admin@int.spoutin.org"
    STEP_CA_PROVISIONER_KEY_PATH: str = "/etc/step-ca/secrets/provisioner_key.json"
    STEP_CA_PASSWORD_FILE: str = "/etc/step-ca/password.txt"
    STEP_CA_PROVISIONER_PASSWORD: str = ""
    STEP_ROOT_CERT_PATH: str = "/etc/step-ca/certs/root_ca.crt"
    STEP_INTERMEDIATE_CERT_PATH: str = "/etc/step-ca/certs/intermediate_ca.crt"
    CERT_VALIDITY_HOURS: str = "52560h"

    # OPNsense FreeRADIUS API
    OPNSENSE_URL: str = "https://opnsense.int.spoutin.org"
    OPNSENSE_API_KEY: str = ""
    OPNSENSE_API_SECRET: str = ""
    OPNSENSE_VERIFY_SSL: bool = False
    OPNSENSE_INTERMEDIATE_CA_REFID: str = ""

    # Slack App (Socket Mode & OAuth)
    SLACK_BOT_TOKEN: str = ""
    SLACK_APP_TOKEN: str = ""
    SLACK_CHANNEL_ID: str = ""
    SLACK_CLIENT_ID: str = ""
    SLACK_CLIENT_SECRET: str = ""
    ADMIN_SLACK_EMAILS: str = "adam@spoutin.org"
    SESSION_SECRET_KEY: str = "spoutin-pki-secret-key-change-me"
    DATABASE_PATH: str = "/opt/pki/data/inventory.db"


# Global singleton settings instance
settings = Settings()
