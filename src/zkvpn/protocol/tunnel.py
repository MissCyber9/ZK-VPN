"""VPN tunnel management with ZK session authentication.

Servers admit clients only after a valid Groth16 session proof (see
``zkvpn.protocol.admission`` and ``zkvpn.zk``). Clients present their ZK
identity during ``connect`` and get their tunnel IP from the server.
"""

import asyncio
import ipaddress
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import logging

from zkvpn.core.config import settings
from zkvpn.core.memory import session_manager, memory_guard
from zkvpn.protocol.admission import AdmissionServer, request_admission
from zkvpn.protocol.killswitch import KillSwitch
from zkvpn.protocol.wireguard import WireGuardInterface, WireGuardPeer, wg_interface
from zkvpn.zk import SessionProof, SessionVerifier

logger = logging.getLogger(__name__)


def _default_server_ip() -> str:
    return str(next(ipaddress.ip_network(settings.network_cidr, strict=False).hosts()))


@dataclass
class TunnelConfig:
    """Tunnel configuration (addresses derive from ``settings.network_cidr``)."""

    network_cidr: str = field(default_factory=lambda: settings.network_cidr)
    client_ip: Optional[str] = None
    server_ip: str = field(default_factory=_default_server_ip)
    mtu: int = 1420
    persistent_keepalive: int = 25
    dns_servers: Optional[List[str]] = None

    def __post_init__(self):
        if self.dns_servers is None:
            self.dns_servers = ["1.1.1.1", "8.8.8.8"]

    @property
    def prefixlen(self) -> int:
        return ipaddress.ip_network(self.network_cidr, strict=False).prefixlen


class ZKTunnel:
    """VPN tunnel with ZK proof admission."""

    def __init__(self, interface: Optional[WireGuardInterface] = None):
        self.interface = interface or wg_interface
        self.config = TunnelConfig()
        self._health_check_task: Optional[asyncio.Task] = None
        self._is_connected = False
        self._current_session = None
        authorized = [i.strip() for i in settings.authorized_identities.split(",") if i.strip()]
        self.auth = SessionVerifier(authorized=authorized or None)
        self.killswitch = KillSwitch(self.interface.interface)
        self.admission: Optional[AdmissionServer] = None
        self.client_ips: Dict[str, str] = {}
        self._client_sessions: Dict[str, str] = {}
        self._admit_lock = asyncio.Lock()

        logger.info("ZK Tunnel initialized")

    def _cidr(self, ip: str) -> str:
        return f"{ip}/{self.config.prefixlen}"

    @memory_guard("tunnel_start")
    async def start_server(self) -> bool:
        """Start the VPN server (and its admission endpoint)."""
        try:
            if not self.interface.is_initialized:
                await self.interface.configure_interface()

            await self.interface.set_address(self._cidr(self.config.server_ip))
            await self._enable_ip_forwarding()

            if settings.require_client_proof:
                self.admission = AdmissionServer(self)
                await self.admission.start()

            self._health_check_task = asyncio.create_task(self._health_check())
            self._is_connected = True
            logger.info(f"ZK-VPN server started on {self.config.server_ip}")
            return True

        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            if self.admission:
                await self.admission.stop()
                self.admission = None
            return False

    @memory_guard("tunnel_connect")
    async def connect(self, peer_endpoint: str, peer_public_key: str, *,
                      identity_sk: Optional[int] = None,
                      admission_port: Optional[int] = None) -> bool:
        """Connect to a VPN server.

        Args:
            peer_endpoint: Server WireGuard endpoint (ip:port)
            peer_public_key: Server's WireGuard public key (pin it out of band)
            identity_sk: ZK identity secret. When given, the client first proves
                itself to the server's admission endpoint, which assigns its IP.
                Without it, the client self-assigns an IP (only works with
                servers that do not require proofs).
            admission_port: TCP port of the admission server
        """
        try:
            if not self.interface.is_initialized:
                await self.interface.configure_interface()

            if identity_sk is not None:
                host = peer_endpoint.rpartition(":")[0].strip("[]")
                client_ip = await request_admission(
                    host, admission_port or settings.admission_port,
                    self.interface.public_key, identity_sk)
            else:
                client_ip = await self._assign_client_ip()
            await self.interface.set_address(self._cidr(client_ip))

            peer = WireGuardPeer(
                public_key=peer_public_key,
                endpoint=peer_endpoint,
                allowed_ips=["0.0.0.0/0", "::/0"],  # Route all traffic
                persistent_keepalive=self.config.persistent_keepalive
            )
            await self.interface.add_peer(peer)

            # Fail closed: without the kill-switch a tunnel drop would leak traffic
            if settings.killswitch_enabled and not await self.killswitch.enable([peer_endpoint]):
                raise RuntimeError("kill-switch could not be enabled")

            self._current_session = session_manager.create_session(peer_public_key)
            self._health_check_task = asyncio.create_task(self._health_check())
            self._is_connected = True
            logger.info(f"Connected to {peer_endpoint} with IP {client_ip}")
            return True

        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            return False

    async def disconnect(self) -> bool:
        """Disconnect / stop the tunnel."""
        try:
            if self._health_check_task:
                self._health_check_task.cancel()
                try:
                    await self._health_check_task
                except asyncio.CancelledError:
                    pass

            if self.admission:
                await self.admission.stop()
                self.admission = None

            # Explicit disconnect: traffic may flow normally again
            await self.killswitch.disable()

            await self.interface.delete_interface()

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

    def issue_challenge(self) -> str:
        """Create a single-use challenge a client must answer with a ZK session proof."""
        return self.auth.issue_challenge()

    async def add_client(self, client_public_key: str, client_ip: Optional[str] = None,
                         *, nonce: Optional[str] = None,
                         proof: Optional[SessionProof] = None) -> bool:
        """Add a client to the server.

        When ``settings.require_client_proof`` is set (default), the client must
        present a valid Groth16 session proof bound to ``nonce`` (from
        ``issue_challenge``) and to ``client_public_key``. On success the
        assigned IP is available in ``self.client_ips[client_public_key]``.
        """
        try:
            if settings.require_client_proof:
                if proof is None or nonce is None:
                    logger.warning("Client refused: ZK session proof required")
                    return False
                result = await self.auth.verify(proof, nonce, client_public_key)
                if not result.valid:
                    logger.warning(f"Client refused: {result.error}")
                    return False

            # Serialise IP assignment so concurrent admissions never share an address
            async with self._admit_lock:
                client_ip = client_ip or self.client_ips.get(client_public_key) \
                    or await self._assign_client_ip()
                peer = WireGuardPeer(
                    public_key=client_public_key,
                    allowed_ips=[f"{client_ip}/32"],
                    persistent_keepalive=self.config.persistent_keepalive
                )
                await self.interface.add_peer(peer)
                self.client_ips[client_public_key] = client_ip

            old = self._client_sessions.pop(client_public_key, None)
            if old:
                session_manager.delete_session(old)
            session = session_manager.create_session(client_public_key)
            self._client_sessions[client_public_key] = session.get("session_id", "")

            logger.info(f"Added client {client_public_key[:8]}... with IP {client_ip}")
            return True

        except Exception as e:
            logger.error(f"Failed to add client: {e}")
            return False

    async def remove_client(self, client_public_key: str) -> bool:
        """Drop one client (peer + session) without tearing the server down."""
        removed = await self.interface.remove_peer(client_public_key)
        self.client_ips.pop(client_public_key, None)
        session_id = self._client_sessions.pop(client_public_key, None)
        if session_id:
            session_manager.delete_session(session_id)
        return removed

    async def _health_check(self):
        """Periodic health check."""
        while True:
            try:
                await asyncio.sleep(60)
                if not self._is_connected:
                    continue
                status = await self.interface.get_status()
                logger.debug(f"Health check: {len(status.get('peers', []))} peers")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check failed: {e}")

    async def _enable_ip_forwarding(self):
        """Enable IP forwarding on the system."""
        try:
            for key in ("net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1"):
                proc = await asyncio.create_subprocess_exec(
                    "sysctl", "-w", key,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await proc.communicate()
            logger.debug("IP forwarding enabled")
        except Exception as e:
            logger.warning(f"Failed to enable IP forwarding: {e}")

    async def _assign_client_ip(self) -> str:
        """Assign the next free address of the VPN network."""
        network = ipaddress.ip_network(self.config.network_cidr, strict=False)
        status = await self.interface.get_status()
        used = {self.config.server_ip, *self.client_ips.values()}
        for peer in status.get('peers', []):
            for allowed_ip in peer.get('allowed_ips', []):
                used.add(allowed_ip.split('/')[0])

        for host in network.hosts():
            if str(host) not in used:
                return str(host)
        raise RuntimeError("No available IP addresses in network")

    def get_status(self) -> Dict[str, Any]:
        """Get tunnel status."""
        return {
            "connected": self._is_connected,
            "interface": self.interface.interface,
            "address": self.interface.address,
            "public_key": self.interface.public_key,
            "has_session": self._current_session is not None,
            "killswitch": self.killswitch.active,
            "clients": len(self.client_ips),
        }


# Global tunnel instance
tunnel = ZKTunnel()


__all__ = ["ZKTunnel", "TunnelConfig", "tunnel"]
