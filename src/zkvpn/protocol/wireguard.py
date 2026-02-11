"""Native WireGuard interface for ZK-VPN.

This module provides a clean Python interface to WireGuard using the wg(8) command.
All operations are performed via subprocess, no disk writes for sensitive data.
"""

import asyncio
import subprocess
import re
import ipaddress
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
import logging
import secrets
import tempfile
import os
from pathlib import Path

from zkvpn.core.config import settings
from zkvpn.core.memory import memory_guard, key_store

logger = logging.getLogger(__name__)


@dataclass
class WireGuardPeer:
    """WireGuard peer configuration."""
    
    public_key: str
    endpoint: Optional[str] = None
    allowed_ips: List[str] = None
    persistent_keepalive: int = 25
    latest_handshake: Optional[int] = None
    transfer_rx: int = 0
    transfer_tx: int = 0
    
    def __post_init__(self):
        if self.allowed_ips is None:
            self.allowed_ips = ["0.0.0.0/0", "::/0"]


class WireGuardInterface:
    """Native WireGuard interface manager using wg subprocess."""
    
    def __init__(self, interface_name: str = None):
        """Initialize WireGuard interface.
        
        Args:
            interface_name: Name of the WireGuard interface (default: from settings)
        """
        self.interface = interface_name or settings.wireguard_interface
        self.private_key: Optional[str] = None
        self.public_key: Optional[str] = None
        self.listen_port: int = settings.port
        self.address: str = settings.host
        self.peers: Dict[str, WireGuardPeer] = {}
        self._initialized = False
        
        logger.info(f"WireGuard interface initialized: {self.interface}")
    
    @memory_guard("wireguard_keygen")
    def generate_keypair(self) -> Tuple[str, str]:
        """Generate WireGuard keypair.
        
        Returns:
            Tuple[str, str]: (private_key, public_key)
        """
        try:
            # Generate private key
            private_key = subprocess.run(
                ["wg", "genkey"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5
            ).stdout.strip()
            
            # Generate public key
            public_key = subprocess.run(
                ["wg", "pubkey"],
                input=private_key,
                capture_output=True,
                text=True,
                check=True,
                timeout=5
            ).stdout.strip()
            
            self.private_key = private_key
            self.public_key = public_key
            
            # Store in memory only (never on disk)
            key_store.set("wg_private_key", private_key, ttl=86400)
            key_store.set("wg_public_key", public_key, ttl=86400)
            
            logger.info(f"Generated WireGuard keypair: {public_key[:8]}...")
            return private_key, public_key
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("WireGuard key generation timeout")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"WireGuard key generation failed: {e.stderr}")
        except FileNotFoundError:
            raise RuntimeError("WireGuard (wg) not installed. Please install wireguard-tools.")
    
    @memory_guard("wireguard_configure")
    async def configure_interface(self, private_key: Optional[str] = None) -> bool:
        """Configure WireGuard interface.
        
        Args:
            private_key: Private key (generated if not provided)
            
        Returns:
            bool: True if successful
        """
        # Use provided key or generate new one
        if private_key:
            self.private_key = private_key
            # Generate public key from private key
            try:
                self.public_key = subprocess.run(
                    ["wg", "pubkey"],
                    input=self.private_key,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=5
                ).stdout.strip()
            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"Invalid private key: {e.stderr}")
        else:
            self.generate_keypair()
        
        # Create interface if it doesn't exist
        try:
            # Check if interface exists
            result = subprocess.run(
                ["ip", "link", "show", self.interface],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                # Create interface
                subprocess.run(
                    ["ip", "link", "add", self.interface, "type", "wireguard"],
                    check=True,
                    capture_output=True,
                    timeout=5
                )
                logger.info(f"Created interface {self.interface}")
            
            # Configure WireGuard
            config_cmd = [
                "wg", "set", self.interface,
                "private-key", "/dev/stdin",  # Read from stdin (no disk write)
                "listen-port", str(self.listen_port)
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *config_cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await proc.communicate(input=self.private_key.encode())
            
            if proc.returncode != 0:
                raise RuntimeError(f"Failed to configure WireGuard: {stderr.decode()}")
            
            # Bring interface up
            subprocess.run(
                ["ip", "link", "set", self.interface, "up"],
                check=True,
                capture_output=True,
                timeout=5
            )
            
            # Assign IP address
            subprocess.run(
                ["ip", "addr", "add", self.address, "dev", self.interface],
                capture_output=True,
                timeout=5
            )  # Don't check return code - address might already exist
            
            self._initialized = True
            logger.info(f"WireGuard interface {self.interface} configured successfully")
            return True
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("WireGuard configuration timeout")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"WireGuard configuration failed: {e.stderr}")
        except Exception as e:
            logger.error(f"Failed to configure WireGuard: {e}")
            return False
    
    @memory_guard("wireguard_add_peer")
    async def add_peer(self, peer: WireGuardPeer) -> bool:
        """Add or update a peer.
        
        Args:
            peer: Peer configuration
            
        Returns:
            bool: True if successful
        """
        try:
            # Build allowed IPs string
            allowed_ips_str = ",".join(peer.allowed_ips)
            
            # Add peer
            cmd = [
                "wg", "set", self.interface,
                "peer", peer.public_key,
                "allowed-ips", allowed_ips_str,
                "persistent-keepalive", str(peer.persistent_keepalive)
            ]
            
            if peer.endpoint:
                cmd.extend(["endpoint", peer.endpoint])
            
            subprocess.run(cmd, check=True, capture_output=True, timeout=5)
            
            # Store in memory
            self.peers[peer.public_key] = peer
            key_store.set(f"peer_{peer.public_key[:16]}", peer, ttl=3600)
            
            logger.info(f"Added peer {peer.public_key[:8]}... with allowed IPs: {allowed_ips_str}")
            return True
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("WireGuard add peer timeout")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to add peer: {e.stderr}")
    
    @memory_guard("wireguard_remove_peer")
    async def remove_peer(self, public_key: str) -> bool:
        """Remove a peer.
        
        Args:
            public_key: Peer's public key
            
        Returns:
            bool: True if successful
        """
        try:
            subprocess.run(
                ["wg", "set", self.interface, "peer", public_key, "remove"],
                check=True,
                capture_output=True,
                timeout=5
            )
            
            if public_key in self.peers:
                del self.peers[public_key]
            
            logger.info(f"Removed peer {public_key[:8]}...")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to remove peer: {e.stderr}")
            return False
    
    async def get_status(self) -> Dict[str, any]:
        """Get WireGuard interface status.
        
        Returns:
            Dict: Interface and peers status
        """
        try:
            result = subprocess.run(
                ["wg", "show", self.interface],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                return {"error": "Interface not found"}
            
            # Parse wg show output
            status = {
                "interface": self.interface,
                "public_key": None,
                "listen_port": None,
                "peers": []
            }
            
            current_peer = None
            
            for line in result.stdout.split('\n'):
                if line.startswith('interface:'):
                    pass  # Already have interface name
                elif line.startswith('  public key:'):
                    status['public_key'] = line.split(':')[1].strip()
                elif line.startswith('  listening port:'):
                    status['listen_port'] = int(line.split(':')[1].strip())
                elif line.startswith('peer:'):
                    current_peer = {
                        'public_key': line.split(':')[1].strip(),
                        'endpoint': None,
                        'allowed_ips': [],
                        'latest_handshake': None,
                        'transfer': {'rx': 0, 'tx': 0}
                    }
                    status['peers'].append(current_peer)
                elif current_peer and line.startswith('    endpoint:'):
                    current_peer['endpoint'] = line.split(':')[1].strip()
                elif current_peer and line.startswith('    allowed ips:'):
                    ips = line.split(':')[1].strip()
                    current_peer['allowed_ips'] = [ip.strip() for ip in ips.split(',')]
                elif current_peer and line.startswith('    latest handshake:'):
                    hs = line.split(':')[1].strip()
                    current_peer['latest_handshake'] = hs
                elif current_peer and line.startswith('    transfer:'):
                    # Parse "1.23 KiB received, 4.56 KiB sent"
                    match = re.search(r'([\d.]+)\s*([KMG]iB)?\s*received,\s*([\d.]+)\s*([KMG]iB)?\s*sent', line)
                    if match:
                        rx_val, rx_unit, tx_val, tx_unit = match.groups()
                        current_peer['transfer']['rx'] = self._parse_transfer(rx_val, rx_unit)
                        current_peer['transfer']['tx'] = self._parse_transfer(tx_val, tx_unit)
            
            return status
            
        except subprocess.TimeoutExpired:
            return {"error": "Timeout getting status"}
        except Exception as e:
            logger.error(f"Failed to get status: {e}")
            return {"error": str(e)}
    
    def _parse_transfer(self, value: str, unit: Optional[str]) -> int:
        """Parse transfer value to bytes."""
        val = float(value)
        if unit == 'KiB':
            return int(val * 1024)
        elif unit == 'MiB':
            return int(val * 1024 * 1024)
        elif unit == 'GiB':
            return int(val * 1024 * 1024 * 1024)
        else:
            return int(val)
    
    async def set_address(self, address: str) -> bool:
        """Set interface IP address.
        
        Args:
            address: IP address with CIDR (e.g., "10.0.0.1/24")
            
        Returns:
            bool: True if successful
        """
        try:
            # Remove existing addresses
            subprocess.run(
                ["ip", "addr", "flush", "dev", self.interface],
                capture_output=True,
                timeout=5
            )
            
            # Add new address
            subprocess.run(
                ["ip", "addr", "add", address, "dev", self.interface],
                check=True,
                capture_output=True,
                timeout=5
            )
            
            self.address = address
            logger.info(f"Set interface address to {address}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to set address: {e.stderr}")
            return False
    
    async def delete_interface(self) -> bool:
        """Delete WireGuard interface.
        
        Returns:
            bool: True if successful
        """
        try:
            subprocess.run(
                ["ip", "link", "delete", self.interface],
                check=True,
                capture_output=True,
                timeout=5
            )
            
            self._initialized = False
            logger.info(f"Deleted interface {self.interface}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to delete interface: {e.stderr}")
            return False
    
    @property
    def is_initialized(self) -> bool:
        """Check if interface is initialized."""
        return self._initialized


# Global WireGuard interface instance
wg_interface = WireGuardInterface()


__all__ = ["WireGuardInterface", "WireGuardPeer", "wg_interface"]
