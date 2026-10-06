import re
from enum import Enum, IntEnum
from pydantic import BaseModel, Field, field_validator


class VlanOption(IntEnum):
    LAN = 1
    DMS = 2
    SEMI_PRIVATE = 8
    IOT = 9

    @property
    def label(self) -> str:
        labels = {
            VlanOption.LAN: "1 - LAN",
            VlanOption.DMS: "2 - DMS",
            VlanOption.SEMI_PRIVATE: "8 - SemiPrivate (Default)",
            VlanOption.IOT: "9 - IoT",
        }
        return labels[self]

    @classmethod
    def default(cls) -> "VlanOption":
        return cls.SEMI_PRIVATE


class DevicePlatform(str, Enum):
    ANDROID = "android"
    IOS = "ios"
    MACOS = "macos"
    WINDOWS = "windows"
    OTHER = "other"


RESERVED_NAMES = {
    "admin",
    "administrator",
    "root",
    "radius",
    "freeradius",
    "step-ca",
    "step",
    "opnsense",
    "gateway",
    "router",
    "dns",
    "firewall",
    "nas",
    "ca",
    "server",
    "localhost",
}

HOSTNAME_REGEX = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")


def sanitize_device_name(name: str) -> str:
    """Sanitizes user input into RFC 1123 compliant lowercase hostname."""
    if not name:
        return ""
    # Lowercase and convert spaces/underscores/dots to hyphens
    sanitized = name.strip().lower()
    sanitized = re.sub(r"[\s_.]+", "-", sanitized)
    # Strip any characters that are not a-z, 0-9, or hyphen
    sanitized = re.sub(r"[^a-z0-9-]", "", sanitized)
    # Collapse multiple consecutive hyphens
    sanitized = re.sub(r"-+", "-", sanitized)
    # Strip leading/trailing hyphens
    return sanitized.strip("-")


class EnrollmentRequest(BaseModel):
    device_name: str = Field(
        ...,
        description="Device name (2-32 chars, lowercase alphanumeric + hyphens)",
        examples=["personal-phone"],
    )
    platform: DevicePlatform = Field(
        default=DevicePlatform.OTHER,
        description="Target platform for installation instructions",
    )

    @field_validator("device_name", mode="before")
    @classmethod
    def preprocess_device_name(cls, v: str) -> str:
        if isinstance(v, str):
            return sanitize_device_name(v)
        return v

    @field_validator("device_name")
    @classmethod
    def validate_device_name(cls, v: str) -> str:
        if not v or len(v) < 2 or len(v) > 32:
            raise ValueError("Device name must be between 2 and 32 characters.")

        if not HOSTNAME_REGEX.match(v):
            raise ValueError(
                "Device name must only contain lowercase letters, numbers, and hyphens, "
                "and cannot start or end with a hyphen."
            )

        if v in RESERVED_NAMES:
            raise ValueError(f"'{v}' is a reserved network name. Please pick another name.")

        return v


class EnrollmentStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class StatusResponse(BaseModel):
    request_id: str
    status: EnrollmentStatus
    device_name: str
    vlan_id: int | None = None
    vlan_label: str | None = None
    download_token: str | None = None
    pin: str | None = None
    radius_identity: str | None = None
    radius_domain: str | None = None
    platform: DevicePlatform = DevicePlatform.OTHER
    message: str | None = None
