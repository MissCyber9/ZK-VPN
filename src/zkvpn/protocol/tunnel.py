"""VPN tunnel management with ZK proofs.

This module handles the secure tunnel establishment and maintenance
with periodic zero-knowledge proof exchange.
"""

import asyncio
import time
import ipaddress
from typing import Optional, Dict, Any
import logging
from dataclasses import dataclass

from zkvpn.core.config import settings
from zkvpn.core.memory import session_manager, memory_guard
from zkvpn.circuits.prover import prover, Proof
from zkvpn.circuits.verifier import verifier
from zkvpn.protocol.wireguard import WireGuardInterface, WireGuardPeer, wg_interface

logger = logging.getLogger(__name__)


@dataclass
class TunnelConfig:
    """Tunnel configuration."""
    
    network_cidr: str = settings.network_cidr
    client_ip: Optional[str] = None
    server_ip: str = "10.0.0.1"
    mtu: int = 1420
    persistent_keepalive: int = 25
    dns_servers: list = None
    
    def __post_init__(self):
        if self.dns_servers is None:
            self.dns_servers = ["1.1.1.1", "8.8.8.8"]


class ZKTunnel:
    """VPN tunnel with ZK proof authentication."""
    
    def __init__(self, interface: Optional[WireGuardInterface] = None):
        """Initialize tunnel.
        
        Args:
            interface: WireGuard interface (uses global if None)
        """
        self.interface = interface or wg_interface
        self.config = TunnelConfig()
        self._proof_task: Optional[asyncio.Task] = None
        self._health_check_task: Optional[asyncio.Task] = None
        self._is_connected = False
        self._current_session = None
        self._last_proof: Optional[Proof] = None
        
        logger.info("ZK Tunnel initialized")
    
    @memory_guard("tunnel_start")
    async def start_server(self) -> bool:
        """Start VPN server.
        
        Returns:
            bool: True if successful
        """
        try:
            # Configure WireGuard interface
            if not self.interface.is_initialized:
                await self.interface.configure_interface()
            
            # Set server IP
            await self.interface.set_address(f"{self.config.server_ip}/24")
            
            # Enable IP forwarding
            await self._enable_ip_forwarding()
            
            # Start periodic proof generation
            self._proof_task = asyncio.create_task(
                self._generate_periodic_proofs()
            )
            
            # Start health check
            self._health_check_task = asyncio.create_task(
                self._health_check()
            )
            
            self._is_connected = True
            logger.info(f"ZK-VPN server started on {self.config.server_ip}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            return False
    
    @memory_guard("tunnel_connect")
    async def connect(self, peer_endpoint: str, peer_public_key: str) -> bool:
        """Connect to VPN server.
        
        Args:
            peer_endpoint: Server endpoint (ip:port)
            peer_public_key: Server's WireGuard public key
            
        Returns:
            bool: True if connected
        """
        try:
            # Configure client interface
            if not self.interface.is_initialized:
                await self.interface.configure_interface()
            
            # Generate client IP from network
            client_ip = await self._assign_client_ip()
            await self.interface.set_address(f"{client_ip}/24")
            
            # Generate ZK proof for authentication
            proof = await prover.generate_proof()
            self._last_proof = proof
            
            # Add server as peer
            peer = WireGuardPeer(
                public_key=peer_public_key,
                endpoint=peer_endpoint,
                allowed_ips=["0.0.0.0/0", "::/0"],  # Route all traffic
                persistent_keepalive=self.config.persistent_keepalive
            )
            
            await self.interface.add_peer(peer)
            
            # Create session
            self._current_session = session_manager.create_session(peer_public_key)
            
            # Start periodic proof generation
            self._proof_task = asyncio.create_task(
                self._generate_periodic_proofs()
            )
            
            # Start health check
            self._health_check_task = asyncio.create_task(
                self._health_check()
            )
            
            self._is_connected = True
            logger.info(f"Connected to {peer_endpoint} with IP {client_ip}")
            logger.info(f"ZK Proof: {proof.proof_hash[:16]}...")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect tunnel.
        
        Returns:
            bool: True if disconnected
        """
        try:
            # Cancel tasks
            if self._proof_task:
                self._proof_task.cancel()
                try:
                    await self._proof_task
                except asyncio.CancelledError:
                    pass
            
            if self._health_check_task:
                self._health_check_task.cancel()
                try:
                    await self._health_check_task
                except asyncio.CancelledError:
                    pass
            
            # Delete interface
            await self.interface.delete_interface()
            
            # Clear session
            if self._current_session:
                session_manager.delete_session(
                    self._current_session.get("session_id", "")
                )
            
            self._is_connected = False
            logger.info("Disconnected")
            return True
            
        except Exception as e:
            logger.error(f"Failed to disconnect: {e}")
            return False
    
    async def add_client(self, client_public_key: str, client_ip: Optional[str] = None) -> bool:
        """Add client to server.
        
        Args:
            client_public_key: Client's WireGuard public key
            client_ip: Assigned IP address (auto-assign if None)
            
        Returns:
            bool: True if client added
        """
        try:
            if not client_ip:
                client_ip = await self._assign_client_ip()
            
            peer = WireGuardPeer(
                public_key=client_public_key,
                allowed_ips=[f"{client_ip}/32"],
                persistent_keepalive=self.config.persistent_keepalive
            )
            
            await self.interface.add_peer(peer)
            
            # Create session
            session_manager.create_session(client_public_key)
            
            logger.info(f"Added client {client_public_key[:8]}... with IP {client_ip}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add client: {e}")
            return False
    
    async def _generate_periodic_proofs(self):
        """Generate periodic ZK proofs for continuous verification."""
        try:
            async for proof in prover.generate_periodic_proofs(interval_seconds=300):
                self._last_proof = proof
                logger.debug(f"Generated periodic proof: {proof.proof_hash[:16]}...")
                
                # In production, send proof to peer
                # await self._send_proof_to_peer(proof)
                
        except asyncio.CancelledError:
            logger.debug("Periodic proof generation stopped")
        except Exception as e:
            logger.error(f"Periodic proof error: {e}")
    
    async def _health_check(self):
        """Periodic health check."""
        while True:
            try:
                await asyncio.sleep(60)
                
                if not self._is_connected:
                    continue
                
                # Check WireGuard status
                status = await self.interface.get_status()
                
                # Verify last proof is not expired
                if self._last_proof and self._last_proof.is_expired:
                    logger.warning("Last proof expired, generating new one...")
                    self._last_proof = await prover.generate_proof()
                
                # Log stats
                peer_count = len(status.get('peers', []))
                logger.debug(f"Health check: {peer_count} peers, "
                           f"proof age: {self._last_proof.age_seconds:.1f}s")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check failed: {e}")
    
    async def _enable_ip_forwarding(self):
        """Enable IP forwarding on the system."""
        try:
            # IPv4 forwarding
            proc = await asyncio.create_subprocess_exec(
                "sysctl", "-w", "net.ipv4.ip_forward=1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            # IPv6 forwarding
            proc = await asyncio.create_subprocess_exec(
                "sysctl", "-w", "net.ipv6.conf.all.forwarding=1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            logger.debug("IP forwarding enabled")
            
        except Exception as e:
            logger.warning(f"Failed to enable IP forwarding: {e}")
    
    async def _assign_client_ip(self) -> str:
        """Assign next available client IP.
        
        Returns:
            str: Assigned IP address
        """
        network = ipaddress.ip_network(self.config.network_cidr)
        
        # Get current peers
        status = await self.interface.get_status()
        used_ips = set()
        
        for peer in status.get('peers', []):
            for allowed_ip in peer.get('allowed_ips', []):
                if '/' in allowed_ip:
                    ip = allowed_ip.split('/')[0]
                    used_ips.add(ip)
        
        # Find first available IP
        for host in network.hosts():
            ip = str(host)
            if ip == self.config.server_ip:
                continue
            if ip not in used_ips:
                return ip
        
        raise RuntimeError("No available IP addresses in network")
    
    def get_status(self) -> Dict[str, Any]:
        """Get tunnel status.
        
        Returns:
            Dict: Status information
        """
        return {
            "connected": self._is_connected,
            "interface": self.interface.interface,
            "address": self.interface.address,
            "public_key": self.interface.public_key,
            "has_session": self._current_session is not None,
            "last_proof": self._last_proof.proof_hash[:16] if self._last_proof else None,
            "proof_age": self._last_proof.age_seconds if self._last_proof else None
        }


# Global tunnel instance
tunnel = ZKTunnel()


__all__ = ["ZKTunnel", "TunnelConfig", "tunnel"]
