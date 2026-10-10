"""Client routing and server forwarding/NAT for ZK-VPN.

Client (``RouteManager``): sends *all* traffic through the tunnel the same way
``wg-quick`` does -- two /1 routes (which override the default route without
replacing it) plus a pinned host route so the WireGuard packets to the server
keep using the original path instead of looping into the tunnel.

Server (``ServerNAT``): masquerades tunnel clients, accepts their forwarded
traffic, and drops client-to-client forwarding (clients are isolated by default).

Everything we add is tagged (routing protocol ``252``, dedicated iptables
chains) so teardown is exact and works from a different process.
"""

import asyncio
import ipaddress
import logging
from typing import List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

ROUTE_PROTO = "252"
NAT_CHAIN = "ZKVPN_NAT"
FWD_CHAIN = "ZKVPN_FWD"


async def _exec(*cmd: str) -> Tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    out, _ = await proc.communicate()
    return proc.returncode, out.decode()


def parse_route_get(output: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract ``(gateway, device)`` from ``ip route get`` output."""
    tokens = output.split()
    gateway = tokens[tokens.index("via") + 1] if "via" in tokens else None
    device = tokens[tokens.index("dev") + 1] if "dev" in tokens else None
    return gateway, device


def pin_command(endpoint_ip: str, gateway: Optional[str], device: str) -> List[str]:
    prefix = "/128" if ipaddress.ip_address(endpoint_ip).version == 6 else "/32"
    cmd = ["ip"] + (["-6"] if prefix == "/128" else []) + [
        "route", "replace", endpoint_ip + prefix]
    if gateway:
        cmd += ["via", gateway]
    return cmd + ["dev", device, "proto", ROUTE_PROTO]


class RouteManager:
    """Full-tunnel routing for a client."""

    def __init__(self, interface: str):
        self.interface = interface

    async def enable(self, endpoint_ip: str) -> bool:
        """Route everything through the tunnel; ``endpoint_ip`` must be an IP."""
        try:
            ipaddress.ip_address(endpoint_ip)
        except ValueError:
            logger.error(f"Routes not installed: endpoint {endpoint_ip!r} is not an IP address")
            return False
        v6 = ipaddress.ip_address(endpoint_ip).version == 6
        rc, out = await _exec("ip", *(["-6"] if v6 else []), "route", "get", endpoint_ip)
        gateway, device = parse_route_get(out)
        if rc != 0 or not device:
            logger.error("Routes not installed: no route to the VPN server")
            return False
        if device == self.interface:
            logger.error("Routes not installed: server is already reached through the tunnel")
            return False

        # 1. keep WireGuard's own packets on the original path
        if (await _exec(*pin_command(endpoint_ip, gateway, device)))[0] != 0:
            logger.error("Routes not installed: could not pin the server route")
            return False
        # 2. everything else goes through the tunnel (IPv4 mandatory, IPv6 best effort)
        for net in ("0.0.0.0/1", "128.0.0.0/1"):
            if (await _exec("ip", "route", "replace", net, "dev", self.interface,
                            "proto", ROUTE_PROTO))[0] != 0:
                await self.disable()
                return False
        for net in ("::/1", "8000::/1"):          # keeps IPv6 from leaking around the tunnel
            await _exec("ip", "-6", "route", "replace", net, "dev", self.interface,
                        "proto", ROUTE_PROTO)
        logger.info(f"All traffic routed through {self.interface}")
        return True

    async def disable(self) -> None:
        """Remove every route we installed (idempotent, no state needed)."""
        await _exec("ip", "route", "flush", "proto", ROUTE_PROTO)
        await _exec("ip", "-6", "route", "flush", "proto", ROUTE_PROTO)


def nat_rules(interface: str, network_cidr: str) -> List[Tuple[str, ...]]:
    """iptables commands building the server's NAT + forwarding chains."""
    ipaddress.ip_network(network_cidr, strict=False)  # validate
    return [
        ("iptables", "-t", "nat", "-N", NAT_CHAIN),
        ("iptables", "-t", "nat", "-F", NAT_CHAIN),
        ("iptables", "-t", "nat", "-A", NAT_CHAIN, "-s", network_cidr,
         "!", "-o", interface, "-j", "MASQUERADE"),
        ("iptables", "-N", FWD_CHAIN),
        ("iptables", "-F", FWD_CHAIN),
        ("iptables", "-A", FWD_CHAIN, "-i", interface, "-o", interface, "-j", "DROP"),
        ("iptables", "-A", FWD_CHAIN, "-i", interface, "-j", "ACCEPT"),
        ("iptables", "-A", FWD_CHAIN, "-o", interface, "-m", "conntrack",
         "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"),
        # jumps last, so the chains are complete when they become active
        ("iptables", "-t", "nat", "-D", "POSTROUTING", "-j", NAT_CHAIN),
        ("iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-j", NAT_CHAIN),
        ("iptables", "-D", "FORWARD", "-j", FWD_CHAIN),
        ("iptables", "-I", "FORWARD", "1", "-j", FWD_CHAIN),
    ]


def nat_teardown() -> List[Tuple[str, ...]]:
    return [
        ("iptables", "-t", "nat", "-D", "POSTROUTING", "-j", NAT_CHAIN),
        ("iptables", "-t", "nat", "-F", NAT_CHAIN),
        ("iptables", "-t", "nat", "-X", NAT_CHAIN),
        ("iptables", "-D", "FORWARD", "-j", FWD_CHAIN),
        ("iptables", "-F", FWD_CHAIN),
        ("iptables", "-X", FWD_CHAIN),
    ]


class ServerNAT:
    """Let tunnel clients reach the Internet through the server."""

    def __init__(self, interface: str, network_cidr: str):
        self.interface = interface
        self.network_cidr = network_cidr
        self.active = False

    async def enable(self) -> bool:
        tolerant = lambda c: c[1] in ("-N", "-D") or c[3:4] in (("-N",), ("-D",))
        for cmd in nat_rules(self.interface, self.network_cidr):
            rc, _ = await _exec(*cmd)
            if rc != 0 and not tolerant(cmd):
                logger.error(f"NAT rule failed: {' '.join(cmd)}")
                await self.disable()
                return False
        self.active = True
        return True

    async def disable(self) -> None:
        for cmd in nat_teardown():
            await _exec(*cmd)
        self.active = False


__all__ = ["RouteManager", "ServerNAT", "parse_route_get", "pin_command",
           "nat_rules", "nat_teardown"]
