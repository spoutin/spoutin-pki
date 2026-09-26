from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
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

    # step-ca REST API
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

    # Slack App (Socket Mode & OAuth)
    SLACK_BOT_TOKEN: str = ""
    SLACK_APP_TOKEN: str = ""
    SLACK_CHANNEL_ID: str = ""
    SLACK_CLIENT_ID: str = ""
    SLACK_CLIENT_SECRET: str = ""
    ADMIN_SLACK_EMAILS: str = "adam@spoutin.org"
    SESSION_SECRET_KEY: str = "spoutin-pki-secret-key-change-me"
    DATABASE_PATH: str = "/opt/wifi-enrollment/data/inventory.db"


# Global singleton settings instance
settings = Settings()
