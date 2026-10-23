"""macOS backend (client role): wireguard-go, ifconfig/route, pf, networksetup.

Requires ``brew install wireguard-go wireguard-tools`` and root (``sudo zkvpn connect ...``).
The server role (NAT/forwarding) is not provided on macOS: use Linux or the Docker image.

Status: the command construction and output parsing are unit-tested on every system;
interface creation, addressing and routing are smoke-tested on a real macOS runner in CI.
The pf kill-switch is NOT exercised end to end on a real machine (applying it to a CI runner
would cut the runner's own connection) -- treat it as experimental.
"""

import asyncio
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from zkvpn.core.config import settings
from zkvpn.platform.fsperm import ensure_private_dir, replace_private_file
from zkvpn.platform.net._exec import run
from zkvpn.platform.net.base import CLIENT, DNS, KILLSWITCH, ROUTES, NetBackend, feature_missing
from zkvpn.protocol.dns import DNSProtector, parse_servers
from zkvpn.protocol.wireguard import WireGuardInterface

logger = logging.getLogger(__name__)

WG_RUN_DIR = Path("/var/run/wireguard")
PF_ANCHOR = "com.apple/250.ZKVPN"          # under Apple's default `anchor "com.apple/*"`
PF_DNS_ANCHOR = "com.apple/250.ZKVPN.dns"


# --------------------------------------------------------------------------- pure helpers

def parse_route_get(output: str) -> Tuple[Optional[str], Optional[str]]:
    """``(gateway, interface)`` from ``route -n get <ip>`` output."""
    gateway = interface = None
    for line in output.splitlines():
        key, _, value = line.strip().partition(":")
        if key == "gateway":
            gateway = value.strip() or None
        elif key == "interface":
            interface = value.strip() or None
    return gateway, interface


def pf_rules(interface: str, endpoints: Sequence[str]) -> str:
    """pf ruleset: only loopback, the tunnel, DHCP and the WireGuard server are allowed out."""
    lines = [
        "pass out quick on lo0 all",
        f"pass out quick on {interface} all",
        "pass out quick inet proto udp from any port 68 to any port 67",
    ]
    for endpoint in endpoints:
        host, sep, port = endpoint.rpartition(":")
        if not sep or not port.isdigit():
            raise ValueError(f"Invalid endpoint: {endpoint!r}")
        addr = ipaddress.ip_address(host.strip("[]"))
        family = "inet6" if addr.version == 6 else "inet"
        lines.append(f"pass out quick {family} proto udp to {addr} port {port}")
    lines.append("block drop out all")
    return "\n".join(lines) + "\n"


def pf_dns_rules(interface: str) -> str:
    """pf ruleset blocking plain DNS and DNS-over-TLS everywhere except through the tunnel."""
    return (f"pass out quick on {interface} all\n"
            "block drop out quick proto { udp tcp } to any port { 53 853 }\n")


def parse_pf_token(output: str) -> Optional[str]:
    match = re.search(r"Token\s*:\s*(\d+)", output)
    return match.group(1) if match else None


def parse_network_services(output: str) -> List[str]:
    """Enabled services from ``networksetup -listallnetworkservices`` (disabled ones start with ``*``)."""
    lines = output.splitlines()[1:]                     # first line is an explanatory note
    return [ln.strip() for ln in lines if ln.strip() and not ln.startswith("*")]


def parse_dns_servers(output: str) -> List[str]:
    """Servers from ``networksetup -getdnsservers <service>`` (empty list = automatic/DHCP)."""
    if "aren't any DNS Servers" in output or not output.strip():
        return []
    return [ln.strip() for ln in output.splitlines() if ln.strip()]


def parse_scutil_dns(output: str) -> List[str]:
    servers: List[str] = []
    for match in re.finditer(r"nameserver\[\d+\]\s*:\s*(\S+)", output):
        if match.group(1) not in servers:
            servers.append(match.group(1))
    return servers


def has_global_ipv6(ifconfig_output: str, tunnel: str) -> bool:
    """True if a non-tunnel interface has a global IPv6 address (possible leak)."""
    current = None
    for line in ifconfig_output.splitlines():
        header = re.match(r"^(\S+):\s+flags=", line)
        if header:
            current = header.group(1)
            continue
        match = re.match(r"^\s+inet6\s+(\S+)", line)
        if match and current and current != tunnel and current != "lo0":
            addr = match.group(1).split("%")[0]
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if not (ip.is_link_local or ip.is_loopback):
                return True
    return False


def _state(name: str) -> Path:
    return Path(settings.state_dir) / name


def _load(name: str) -> Dict:
    try:
        return json.loads(_state(name).read_text())
    except (OSError, ValueError):
        return {}


def _save(name: str, data: Dict) -> None:
    ensure_private_dir(settings.state_dir)
    replace_private_file(_state(name), json.dumps(data))


def _clear(name: str) -> None:
    try:
        _state(name).unlink()
    except FileNotFoundError:
        pass


# --------------------------------------------------------------------------- components

class MacInterface(WireGuardInterface):
    """WireGuard through wireguard-go; the OS picks the ``utunN`` name."""

    def __init__(self, interface_name: str = None):
        super().__init__(interface_name)
        self._requested = self.interface
        self._ip: Optional[str] = None
        # `connect` and `disconnect` are separate processes: recover the utunN name chosen earlier
        try:
            real = _state(f"{self._requested}.name").read_text().strip()
            if re.fullmatch(r"utun\d+", real):
                self.interface = real
        except OSError:
            pass

    async def _create_link(self) -> None:
        wgo = shutil.which("wireguard-go")
        if not wgo:
            raise RuntimeError("wireguard-go not found: brew install wireguard-go wireguard-tools")
        ensure_private_dir(settings.state_dir)
        name_file = _state(f"{self._requested}.name")
        name_file.unlink(missing_ok=True)
        env = {**os.environ, "WG_TUN_NAME_FILE": str(name_file)}
        await asyncio.to_thread(subprocess.run, [wgo, "utun"], env=env, check=True,
                                capture_output=True, timeout=20)
        real = ""
        for _ in range(50):                      # the daemon writes the name once the tun exists
            if name_file.exists():
                real = name_file.read_text().strip()
                if real:
                    break
            await asyncio.sleep(0.1)
        if not re.fullmatch(r"utun\d+", real):
            raise RuntimeError(f"wireguard-go did not report its interface (got {real!r})")
        self.interface = real
        logger.info(f"Created userspace interface {real} (wireguard-go)")

    async def _activate(self) -> None:
        await self.bring_up(strict=True)

    async def bring_up(self, strict: bool = False) -> None:
        rc, _, err = await run("ifconfig", self.interface, "up")
        if rc != 0 and strict:
            raise RuntimeError(f"ifconfig up failed: {err.strip()}")

    async def _assign_address(self, address: str) -> None:
        ifc = ipaddress.ip_interface(address)
        if self._ip and self._ip != str(ifc.ip):
            await run("ifconfig", self.interface, "inet", self._ip, "-alias")
        rc, _, err = await run("ifconfig", self.interface, "inet", str(ifc.ip), str(ifc.ip),
                               "netmask", str(ifc.network.netmask), "alias")
        if rc != 0:
            raise subprocess.CalledProcessError(rc, "ifconfig", stderr=err.encode())
        await run("route", "-q", "-n", "add", "-inet", str(ifc.network), "-interface", self.interface)
        self._ip = str(ifc.ip)

    async def _remove_link(self) -> None:
        # wireguard-go exits when its control socket disappears (this is what wg-quick does)
        (WG_RUN_DIR / f"{self.interface}.sock").unlink(missing_ok=True)
        _state(f"{self._requested}.name").unlink(missing_ok=True)


class MacRouteManager:
    """All traffic through the tunnel: two /1 routes plus a pinned host route to the server."""

    def __init__(self, interface: str):
        self.interface = interface

    async def enable(self, endpoint_ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(endpoint_ip)
        except ValueError:
            logger.error(f"Routes not installed: endpoint {endpoint_ip!r} is not an IP address")
            return False
        family = ["-inet6"] if addr.version == 6 else []
        rc, out, _ = await run("route", "-n", "get", *family, endpoint_ip)
        gateway, device = parse_route_get(out)
        if rc != 0 or not device:
            logger.error("Routes not installed: no route to the VPN server")
            return False
        if device == self.interface:
            logger.error("Routes not installed: server is already reached through the tunnel")
            return False
        _save("routes.json", {"endpoint": endpoint_ip, "interface": self.interface})
        pin = (["route", "-n", "add", *family, "-host", endpoint_ip, gateway] if gateway
               else ["route", "-n", "add", *family, "-host", endpoint_ip, "-interface", device])
        if (await run(*pin))[0] != 0:
            await self.disable()
            logger.error("Routes not installed: could not pin the server route")
            return False
        for net in ("0.0.0.0/1", "128.0.0.0/1"):
            if (await run("route", "-q", "-n", "add", "-inet", net, "-interface", self.interface))[0] != 0:
                await self.disable()
                return False
        for net in ("::/1", "8000::/1"):          # IPv6 must not bypass the tunnel (best effort)
            await run("route", "-q", "-n", "add", "-inet6", net, "-interface", self.interface)
        return True

    async def disable(self) -> None:
        state = _load("routes.json")
        iface = state.get("interface") or self.interface
        for net in ("0.0.0.0/1", "128.0.0.0/1"):
            await run("route", "-q", "-n", "delete", "-inet", net, "-interface", iface)
        for net in ("::/1", "8000::/1"):
            await run("route", "-q", "-n", "delete", "-inet6", net, "-interface", iface)
        endpoint = state.get("endpoint")
        if endpoint:
            family = ["-inet6"] if ":" in endpoint else []
            await run("route", "-n", "delete", *family, "-host", endpoint)
        _clear("routes.json")


async def _pf_load(anchor: str, rules: str, state_name: str) -> bool:
    rc, out, err = await run("pfctl", "-E")
    token = parse_pf_token(out + err)
    state = {"token": token, "anchor": anchor}
    _save(state_name, state)                    # persisted before the rules take effect
    rc, _, err = await run("pfctl", "-a", anchor, "-f", "-", input_text=rules)
    if rc != 0:
        logger.error(f"pfctl failed to load {anchor}: {err.strip()}")
        await _pf_unload(anchor, state_name)
        return False
    return True


async def _pf_unload(anchor: str, state_name: str) -> None:
    state = _load(state_name)
    await run("pfctl", "-a", anchor, "-F", "all")
    if state.get("token"):
        await run("pfctl", "-X", state["token"])
    _clear(state_name)


class MacKillSwitch:
    """Block everything but the tunnel and the WireGuard server (pf anchor)."""

    def __init__(self, interface: str):
        self.interface = interface
        self.active = False

    async def enable(self, endpoints: Sequence[str]) -> bool:
        try:
            rules = pf_rules(self.interface, endpoints)
        except ValueError as e:
            logger.error(f"Kill-switch not enabled: {e}")
            return False
        self.active = await _pf_load(PF_ANCHOR, rules, "killswitch.json")
        return self.active

    async def disable(self) -> None:
        await _pf_unload(PF_ANCHOR, "killswitch.json")
        self.active = False


class MacDNSProtector(DNSProtector):
    """DNS through the tunnel with ``networksetup``; plain DNS blocked elsewhere with pf."""

    async def detect_backend(self) -> str:
        return "networksetup"

    async def _apply(self, backend: str, state: Dict) -> None:
        rc, out, err = await run("networksetup", "-listallnetworkservices")
        if rc != 0:
            raise RuntimeError(f"networksetup failed: {err.strip()}")
        services = parse_network_services(out)
        saved: Dict[str, List[str]] = {}
        for service in services:
            _, current, _ = await run("networksetup", "-getdnsservers", service)
            saved[service] = parse_dns_servers(current)
        state["services"] = saved
        self._save_state(state)                  # original DNS settings persisted BEFORE changing them
        for service in services:
            rc, _, err = await run("networksetup", "-setdnsservers", service, *self._dns_servers)
            if rc != 0:
                raise RuntimeError(f"setdnsservers {service!r} failed: {err.strip()}")
        await run("dscacheutil", "-flushcache")

    async def _revert(self, state: Dict) -> None:
        for service, servers in (state.get("services") or {}).items():
            await run("networksetup", "-setdnsservers", service, *(servers or ["Empty"]))
        await run("dscacheutil", "-flushcache")

    async def _block_dns_leaks(self) -> None:
        if not await _pf_load(PF_DNS_ANCHOR, pf_dns_rules(self.interface), "dns-pf.json"):
            raise RuntimeError("could not install the DNS firewall rules")

    async def _remove_dns_blocks(self) -> None:
        await _pf_unload(PF_DNS_ANCHOR, "dns-pf.json")

    async def _get_current_dns_servers(self) -> List[str]:
        _, out, _ = await run("scutil", "--dns")
        return parse_scutil_dns(out)

    async def _check_ipv6(self) -> bool:
        _, out, _ = await run("ifconfig", "-a")
        return has_global_ipv6(out, self.interface)


def make_backend() -> NetBackend:
    missing = feature_missing("server role", "macOS")
    return NetBackend(
        name="macOS",
        features=frozenset({CLIENT, ROUTES, KILLSWITCH, DNS}),
        make_interface=MacInterface,
        make_routes=MacRouteManager,
        make_killswitch=MacKillSwitch,
        make_dns=MacDNSProtector,
        make_nat=missing,
        notes="client role; needs wireguard-go + wireguard-tools and root; kill-switch experimental",
    )
