"""Tests for ZK-VPN configuration module."""

import os
import secrets
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from zkvpn.core.config import Settings, get_settings


class TestSettings:
    """Test suite for Settings class."""
    
    def test_default_settings(self):
        """Test settings with default values."""
        settings = Settings()
        
        assert settings.port == 51820
        assert settings.host == "0.0.0.0"
        assert settings.log_level == "INFO"
        assert settings.proof_ttl_seconds == 3600
        assert settings.wireguard_interface == "zkvpn0"
        assert settings.node_id.startswith("node-")
        assert len(settings.node_id) > 10
    
    def test_env_variable_override(self):
        """Test environment variable override."""
        os.environ["ZKVPN_PORT"] = "12345"
        os.environ["ZKVPN_LOG_LEVEL"] = "DEBUG"
        os.environ["ZKVPN_WIREGUARD_INTERFACE"] = "wg-test"
        
        settings = Settings()
        
        assert settings.port == 12345
        assert settings.log_level == "DEBUG"
        assert settings.wireguard_interface == "wg-test"
        
        # Cleanup
        del os.environ["ZKVPN_PORT"]
        del os.environ["ZKVPN_LOG_LEVEL"]
        del os.environ["ZKVPN_WIREGUARD_INTERFACE"]
    
    def test_env_file_loading(self):
        """Test loading from .env file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env") as f:
            f.write("ZKVPN_NODE_ID=test-node-123\n")
            f.write("ZKVPN_PORT=9999\n")
            f.write("ZKVPN_NETWORK_CIDR=10.10.0.0/16\n")
            f.flush()
            
            settings = Settings(_env_file=f.name)
            
            assert settings.node_id == "test-node-123"
            assert settings.port == 9999
            assert settings.network_cidr == "10.10.0.0/16"
    
    def test_node_id_auto_generation(self):
        """Test automatic node_id generation."""
        # Empty string should trigger generation
        settings = Settings(node_id="")
        assert settings.node_id.startswith("node-")
        assert settings.node_id != "node-"
        
        # Whitespace should trigger generation
        settings = Settings(node_id="   ")
        assert settings.node_id.startswith("node-")
        
        # None should trigger generation
        settings = Settings(node_id=None)
        assert settings.node_id.startswith("node-")
    
    def test_port_validation(self):
        """Test port number validation."""
        # Valid ports
        Settings(port=1024)
        Settings(port=65535)
        Settings(port=51820)
        
        # Invalid ports
        with pytest.raises(ValidationError):
            Settings(port=1023)  # Too low
        
        with pytest.raises(ValidationError):
            Settings(port=65536)  # Too high
        
        with pytest.raises(ValidationError):
            Settings(port=0)  # Invalid
    
    def test_cidr_validation(self):
        """Test CIDR notation validation."""
        # Valid CIDRs
        Settings(network_cidr="10.0.0.0/24")
        Settings(network_cidr="192.168.1.0/24")
        Settings(network_cidr="172.16.0.0/12")
        
        # Invalid CIDRs
        with pytest.raises(ValidationError):
            Settings(network_cidr="invalid")
        
        with pytest.raises(ValidationError):
            Settings(network_cidr="10.0.0.0/33")  # /33 invalid for IPv4
        
        with pytest.raises(ValidationError):
            Settings(network_cidr="300.0.0.0/24")  # Invalid IP
    
    def test_config_dir_sanitization(self):
        """Test config directory path sanitization."""
        # Valid paths
        Settings(wireguard_config_dir="/etc/wireguard")
        Settings(wireguard_config_dir="./wireguard")
        
        # Path traversal attempts
        with pytest.raises(ValidationError):
            Settings(wireguard_config_dir="/etc/../etc/wireguard")
        
        with pytest.raises(ValidationError):
            Settings(wireguard_config_dir="../../etc/wireguard")
    
    def test_private_key_handling(self):
        """Test private key secure handling."""
        # Auto-generation
        settings = Settings()
        assert settings.private_key is not None
        assert settings.get_private_key() is not None
        assert len(settings.get_private_key()) > 20
        
        # Manual setting
        test_key = secrets.token_urlsafe(32)
        settings = Settings(private_key=test_key)
        assert settings.get_private_key() == test_key
    
    def test_redact_sensitive(self):
        """Test sensitive data redaction."""
        settings = Settings(private_key="supersecretkey123")
        redacted = settings.redact_sensitive()
        
        assert redacted["private_key"] == "***REDACTED***"
        assert "supersecretkey123" not in str(redacted)
    
    def test_range_validation(self):
        """Test numeric range validations."""
        # Valid ranges
        Settings(proof_ttl_seconds=60)
        Settings(proof_ttl_seconds=3600)
        Settings(proof_ttl_seconds=86400)
        
        # Invalid ranges
        with pytest.raises(ValidationError):
            Settings(proof_ttl_seconds=59)  # Too low
        
        with pytest.raises(ValidationError):
            Settings(proof_ttl_seconds=86401)  # Too high
        
        with pytest.raises(ValidationError):
            Settings(max_sessions=0)  # Too low
        
        with pytest.raises(ValidationError):
            Settings(max_sessions=101)  # Too high
    
    def test_settings_singleton(self):
        """Test settings singleton pattern."""
        settings1 = get_settings()
        settings2 = get_settings()
        
        assert settings1 is settings2
        assert id(settings1) == id(settings2)
    
    @patch.dict(os.environ, {"ZKVPN_LOG_LEVEL": "INVALID"}, clear=True)
    def test_invalid_log_level(self):
        """Test invalid log level validation."""
        with pytest.raises(ValidationError):
            Settings()
    
    def test_performance_settings(self):
        """Test performance-related settings."""
        settings = Settings(
            memory_max_mb=100,
            cpu_quota_percent=25
        )
        
        assert settings.memory_max_mb == 100
        assert settings.cpu_quota_percent == 25
        
        # Out of range
        with pytest.raises(ValidationError):
            Settings(memory_max_mb=49)
        
        with pytest.raises(ValidationError):
            Settings(cpu_quota_percent=4)
    
    def test_metrics_settings(self):
        """Test metrics configuration."""
        # Disabled by default
        settings = Settings()
        assert settings.metrics_enabled is False
        
        # Enable with custom port
        settings = Settings(metrics_enabled=True, metrics_port=9091)
        assert settings.metrics_enabled is True
        assert settings.metrics_port == 9091
        
        # Invalid port
        with pytest.raises(ValidationError):
            Settings(metrics_enabled=True, metrics_port=80)  # Privileged port
    
    def test_circuit_path_handling(self):
        """Test ZK circuit path configuration."""
        settings = Settings(circuit_path="/opt/zkvpn/circuits")
        assert settings.circuit_path == "/opt/zkvpn/circuits"
        
        settings = Settings(circuit_path="./custom_circuits")
        assert settings.circuit_path == "./custom_circuits"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])