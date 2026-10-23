"""Network kill-switch for ZK-VPN.

While active, the only traffic allowed out of the host is: loopback, anything
leaving through the VPN interface, and the WireGuard handshake/transport UDP
packets to the VPN server itself. Everything else (including DNS, DoT, DoH,
IPv6) is dropped, so a tunnel failure cannot leak traffic in clear.

Rules live in a dedicated ``ZKVPN_KILLSWITCH`` chain that is jumped to from
``OUTPUT`` last, so a half-built chain is never active.
"""

import asyncio
import ipaddress
import logging
from typing import List, Optional, Sequence, Tuple

from zkvpn.core.config import settings

logger = logging.getLogger(__name__)

CHAIN = "ZKVPN_KILLSWITCH"
Command = Tuple[str, ...]


def parse_endpoint(endpoint: str) -> Tuple[ipaddress._BaseAddress, int]:
    """Split ``ip:port`` / ``[ipv6]:port`` into (address, port).

    Hostnames are rejected on purpose: resolve them before enabling the
    kill-switch, otherwise DNS would need to leak to reach the server.
    """
    host, sep, port = endpoint.rpartition(":")
    if not sep or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError(f"Invalid endpoint: {endpoint!r}")
    return ipaddress.ip_address(host.strip("[]")), int(port)


def build_rules(interface: str, endpoints: Sequence[str]) -> List[Command]:
    """Commands that (re)build the kill-switch chain, ending with the OUTPUT jump."""
    parsed = [parse_endpoint(e) for e in endpoints]
    cmds: List[Command] = []
    for tool, version in (("iptables", 4), ("ip6tables", 6)):
        cmds += [
            (tool, "-N", CHAIN),                      # may already exist
            (tool, "-F", CHAIN),
            (tool, "-A", CHAIN, "-o", "lo", "-j", "ACCEPT"),
            (tool, "-A", CHAIN, "-o", interface, "-j", "ACCEPT"),
        ]
        for addr, port in parsed:
            if addr.version == version:
                cmds.append((tool, "-A", CHAIN, "-d", str(addr), "-p", "udp",
                             "--dport", str(port), "-j", "ACCEPT"))
        cmds.append((tool, "-A", CHAIN, "-j", "DROP"))
    for tool in ("iptables", "ip6tables"):
        cmds.append((tool, "-D", "OUTPUT", "-j", CHAIN))   # avoid duplicate jump
        cmds.append((tool, "-I", "OUTPUT", "1", "-j", CHAIN))
    return cmds


def teardown_rules() -> List[Command]:
    cmds: List[Command] = []
    for tool in ("iptables", "ip6tables"):
        cmds += [(tool, "-D", "OUTPUT", "-j", CHAIN),
                 (tool, "-F", CHAIN),
                 (tool, "-X", CHAIN)]
    return cmds


class KillSwitch:
    """Enable/disable the firewall kill-switch."""

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface or settings.wireguard_interface
        self.active = False

    async def _run(self, cmd: Command) -> int:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        return await proc.wait()

    async def enable(self, endpoints: Sequence[str]) -> bool:
        """Activate the kill-switch; returns False (and rolls back) on failure."""
        try:
            cmds = build_rules(self.interface, endpoints)
        except ValueError as e:
            logger.error(f"Kill-switch not enabled: {e}")
            return False
        # Commands that are allowed to fail: chain already exists / no old jump.
        tolerant = lambda c: c[1] in ("-N", "-D")
        for cmd in cmds:
            if await self._run(cmd) != 0 and not tolerant(cmd):
                logger.error(f"Kill-switch rule failed: {' '.join(cmd)}")
                await self.disable()
                return False
        self.active = True
        logger.info("Kill-switch enabled")
        return True

    async def disable(self) -> None:
        """Remove every kill-switch rule (best effort, idempotent)."""
        for cmd in teardown_rules():
            await self._run(cmd)
        self.active = False
        logger.info("Kill-switch disabled")


killswitch = KillSwitch()

__all__ = ["KillSwitch", "killswitch", "build_rules", "teardown_rules", "parse_endpoint"]
