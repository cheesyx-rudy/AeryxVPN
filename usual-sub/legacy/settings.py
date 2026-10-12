"""Validated environment settings for proxy probing."""
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ProbeSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="XRAY_", case_sensitive=False, extra="ignore")

    ping_type: str = "proxy_get"
    ping_mode: str = "keepalive"
    ping_url: str = "https://www.gstatic.com/generate_204"
    ping_timeout: float = Field(default=8.0, gt=0, le=60)
    test_timeout: float = Field(default=9.0, gt=0, le=120)
    workers: int = Field(default=16, ge=1, le=128)
    min_valid_configs: int = Field(default=5, ge=0)

    @field_validator("ping_type")
    @classmethod
    def validate_ping_type(cls, value: str) -> str:
        value = value.lower().strip()
        if value not in {"proxy_get", "proxy_head", "tcp", "icmp"}:
            raise ValueError("XRAY_PING_TYPE must be proxy_get, proxy_head, tcp, or icmp")
        return value

    @field_validator("ping_mode")
    @classmethod
    def validate_ping_mode(cls, value: str) -> str:
        value = value.lower().strip()
        if value not in {"keepalive", "double"}:
            raise ValueError("XRAY_PING_MODE must be keepalive or double")
        return value


settings = ProbeSettings()
