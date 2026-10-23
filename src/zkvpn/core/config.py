"""Configuration management for ZK-VPN.

This module implements 12-factor configuration using environment variables.
No sensitive data is ever written to disk. All secrets are handled as SecretStr
and never displayed in logs.
"""

import os
import secrets
from pathlib import Path
import logging
from typing import Optional, Literal, Dict, Any
from functools import lru_cache

from pydantic import Field, SecretStr, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from zkvpn.platform import paths as platform_paths

# Configure module logger
logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Application settings loaded from environment variables.
    
    All configuration follows the 12-factor methodology:
    - Stored in environment variables
    - No hardcoded secrets
    - Environment specific
    """
    
    # ============ NODE CONFIGURATION ============
    node_id: str = Field(
        default_factory=lambda: f"node-{secrets.token_hex(8)}",
        description="Unique node identifier (auto-generated if not provided)"
    )
    port: int = Field(
        51820, 
        ge=1024, 
        le=65535,
        description="WireGuard listening port"
    )
    host: str = Field(
        "0.0.0.0",
        description="Bind address for WireGuard interface"
    )
    
    # ============ SECURITY ============
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        "INFO",
        description="Logging verbosity level"
    )
    proof_ttl_seconds: int = Field(
        3600, 
        ge=60, 
        le=86400,
        description="Time-to-live for ZK proofs in cache"
    )
    session_timeout_seconds: int = Field(
        7200,
        ge=300,
        le=86400,
        description="Session timeout before forced reauthentication"
    )
    max_sessions: int = Field(
        10,
        ge=1,
        le=100,
        description="Maximum concurrent VPN sessions"
    )
    
    # ============ WIREGUARD ============
    wireguard_interface: str = Field(
        "zkvpn0",
        description="WireGuard interface name"
    )
    wireguard_config_dir: str = Field(
        default_factory=lambda: str(platform_paths.wireguard_config_dir()),
        description="Directory for WireGuard configuration"
    )
    private_key: Optional[SecretStr] = Field(
        None,
        description="WireGuard private key (auto-generated if not provided)"
    )
    network_cidr: str = Field(
        "10.0.0.0/24",
        description="VPN network CIDR"
    )
    
    # ============ ZK CIRCUITS ============
    admission_port: int = Field(
        51821,
        ge=1024,
        le=65535,
        description="TCP port of the ZK admission server"
    )
    server_nat_enabled: bool = Field(
        True,
        description="Server masquerades tunnel clients and forwards their traffic (clients are isolated from each other)"
    )
    dns_servers: str = Field(
        "1.1.1.1,1.0.0.1",
        description="Comma-separated DNS servers used inside the tunnel"
    )
    dns_backend: Literal["auto", "resolved", "resolvconf", "file"] = Field(
        "auto",
        description="How the resolver is configured (auto-detected: systemd-resolved, resolvconf, or resolv.conf)"
    )
    state_dir: str = Field(
        default_factory=lambda: str(platform_paths.state_dir()),
        description="RAM-backed directory (tmpfs) holding what is needed to undo network changes across processes"
    )
    dns_protection_enabled: bool = Field(
        True,
        description="Client points DNS at the tunnel and blocks DNS outside it"
    )
    killswitch_enabled: bool = Field(
        True,
        description="Block all non-tunnel traffic while connected as a client"
    )
    zk_dir: str = Field(
        default_factory=lambda: str(platform_paths.zk_dir()),
        description="Directory with the ZK toolchain and build/ artifacts (create it with `zkvpn zk setup`)"
    )
    require_client_proof: bool = Field(
        True,
        description="Server refuses clients that do not present a valid ZK session proof"
    )
    authorized_identities: str = Field(
        "",
        description="Comma-separated ZK identities (decimal pk) allowed to connect; empty = any valid identity"
    )
    proof_generation_timeout: float = Field(
        2.0,
        ge=0.1,
        le=10.0,
        description="Maximum time for proof generation (seconds)"
    )
    
    # ============ PERFORMANCE ============
    memory_max_mb: int = Field(
        150,
        ge=50,
        le=500,
        description="Maximum memory usage in MB"
    )
    cpu_quota_percent: int = Field(
        10,
        ge=5,
        le=100,
        description="CPU quota percentage"
    )
    
    # ============ MONITORING ============
    metrics_enabled: bool = Field(
        False,
        description="Enable Prometheus metrics"
    )
    metrics_port: int = Field(
        9090,
        ge=1024,
        le=65535,
        description="Metrics endpoint port"
    )
    
    model_config = SettingsConfigDict(
        env_prefix="ZKVPN_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        validate_default=True
    )
    
    @field_validator("node_id", mode="before")
    @classmethod
    def validate_node_id(cls, v: Optional[str]) -> str:
        """Ensure node_id is never empty."""
        if not v or v.strip() == "":
            generated = f"node-{secrets.token_hex(8)}"
            logger.info(f"Generated node_id: {generated[:12]}...")
            return generated
        return v.strip()
    
    @field_validator("wireguard_config_dir")
    @classmethod
    def validate_config_dir(cls, v: str) -> str:
        """Validate and sanitize config directory path."""
        # Reject traversal before normalising (normpath would collapse "..")
        if ".." in v.replace("\\", "/").split("/"):
            raise ValueError("Path traversal detected in wireguard_config_dir")
        return os.path.normpath(v)
    
    @field_validator("network_cidr")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        """Basic CIDR validation."""
        import ipaddress
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR notation: {e}")
        return v
    
    def get_private_key(self) -> Optional[str]:
        """Get private key value securely.
        
        Returns:
            Optional[str]: Private key or None if not set
        """
        if self.private_key:
            return self.private_key.get_secret_value()
        return None
    
    def redact_sensitive(self) -> Dict[str, Any]:
        """Return configuration with sensitive values redacted.
        
        Returns:
            Dict[str, Any]: Safe configuration for logging
        """
        config_dict = self.model_dump()
        # Redact sensitive fields
        config_dict["private_key"] = "***REDACTED***" if config_dict.get("private_key") else None
        return config_dict
    
    def __init__(self, **kwargs):
        """Initialize settings with secure defaults."""
        super().__init__(**kwargs)
        
        # The private key is NOT auto-generated here: WireGuardInterface
        # generates a valid keypair with `wg genkey` when none is configured.
        
        # Log non-sensitive configuration
        safe_config = self.redact_sensitive()
        logger.debug(f"Configuration loaded: {safe_config}")


# Settings that must come from the environment / a secret manager, never be
# written to the .env file by the CLI.
SECRET_SETTINGS = frozenset({"private_key"})


def validate_setting(key: str, value: str) -> str:
    """Validate a ``config set`` request; returns the normalised env var name.

    Raises:
        ValueError: unknown key, secret key, control characters in the value,
            or a value that the Settings model rejects.
    """
    key = key.strip().lower()
    if key not in Settings.model_fields:
        raise ValueError(f"Unknown setting: {key!r}")
    if key in SECRET_SETTINGS:
        raise ValueError(
            f"{key} is a secret: set ZKVPN_{key.upper()} in the service environment, "
            "not through the CLI")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Value must not contain control characters or newlines")
    try:
        Settings(**{key: value})
    except ValidationError as e:
        problems = [err["msg"] for err in e.errors() if err["loc"] and err["loc"][0] == key]
        if problems:
            raise ValueError(f"Invalid value for {key}: {'; '.join(problems)}")
        raise
    return f"ZKVPN_{key.upper()}"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance.
    
    Returns:
        Settings: Application settings singleton
    """
    return Settings()


# Export singleton instance
settings = get_settings()


__all__ = ["Settings", "settings", "get_settings", "validate_setting"]