"""Windows backend (client role): WireGuard tunnel service, netsh, PowerShell (NetTCPIP/NetSecurity/DnsClient).

Requires WireGuard for Windows (``winget install WireGuard.WireGuard``: provides ``wg.exe`` and
``wireguard.exe``) and an elevated (Administrator) terminal. The server role (NAT/forwarding)
is not provided on Windows: use Linux or the Docker image.

Status: command construction and output parsing are unit-tested on every system; interface
creation, addressing and routing are smoke-tested on a real Windows runner in CI. The firewall
kill-switch is NOT exercised end to end on a real machine (applying it to a CI runner would
cut the runner's own connection) -- treat it as experimental.
"""

import asyncio
import ipaddress
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from zkvpn.core.config import settings
from zkvpn.platform.fsperm import ensure_private_dir, replace_private_file, write_private_file
from zkvpn.platform.net._exec import check_name, powershell, ps_quote, run
from zkvpn.platform.net.base import CLIENT, DNS, KILLSWITCH, ROUTES, NetBackend, feature_missing
from zkvpn.protocol.dns import DNSProtector
from zkvpn.protocol.wireguard import WireGuardInterface

logger = logging.getLogger(__name__)

FW_GROUP = "ZKVPN"
FW_DNS_GROUP = "ZKVPN-DNS"


# --------------------------------------------------------------------------- pure helpers

def wireguard_exe() -> Optional[str]:
    """Path of wireguard.exe (PATH, then the default install directory)."""
    found = shutil.which("wireguard") or shutil.which("wireguard.exe")
    if found:
        return found
    for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramW6432"), r"C:\Program Files"):
        if base and (Path(base) / "WireGuard" / "wireguard.exe").exists():
            return str(Path(base) / "WireGuard" / "wireguard.exe")
    return None


def tunnel_config(private_key: str, listen_port: int) -> str:
    """Minimal tunnel configuration; peers, address and routes are added at run time."""
    return f"[Interface]\nPrivateKey = {private_key}\nListenPort = {int(listen_port)}\n"


def parse_find_netroute(output: str) -> Tuple[Optional[int], Optional[str]]:
    """``(interface index, next hop)`` from ``Find-NetRoute ... | ConvertTo-Json`` output."""
    try:
        data = json.loads(output)
    except ValueError:
        return None, None
    if isinstance(data, list):
        data = data[0] if data else {}
    index = data.get("InterfaceIndex")
    hop = data.get("NextHop")
    return (int(index) if index is not None else None), hop


def new_route_script(prefix: str, next_hop: str, *, alias: str = None, index: int = None,
                     metric: int = 1) -> str:
    ipaddress.ip_network(prefix, strict=False)
    ipaddress.ip_address(next_hop)
    target = f"-InterfaceAlias {ps_quote(check_name(alias))}" if alias else f"-InterfaceIndex {int(index)}"
    return (f"New-NetRoute -DestinationPrefix {ps_quote(prefix)} {target} -NextHop {ps_quote(next_hop)} "
            f"-RouteMetric {int(metric)} -PolicyStore ActiveStore -ErrorAction Stop | Out-Null")


def remove_route_script(prefix: str) -> str:
    ipaddress.ip_network(prefix, strict=False)
    return (f"Remove-NetRoute -DestinationPrefix {ps_quote(prefix)} -Confirm:$false "
            "-ErrorAction SilentlyContinue")


def killswitch_enable_script(alias: str, endpoints: Sequence[str]) -> str:
    """Allow rules first, default-block last (so the policy is never half applied)."""
    lines = [
        f"New-NetFirewallRule -DisplayName 'ZKVPN tunnel' -Group {FW_GROUP} -Direction Outbound "
        f"-Action Allow -InterfaceAlias {ps_quote(check_name(alias))} | Out-Null",
        f"New-NetFirewallRule -DisplayName 'ZKVPN dhcp' -Group {FW_GROUP} -Direction Outbound "
        "-Action Allow -Protocol UDP -LocalPort 68 -RemotePort 67 | Out-Null",
    ]
    for n, endpoint in enumerate(endpoints):
        host, sep, port = endpoint.rpartition(":")
        if not sep or not port.isdigit():
            raise ValueError(f"Invalid endpoint: {endpoint!r}")
        addr = ipaddress.ip_address(host.strip("[]"))
        lines.append(
            f"New-NetFirewallRule -DisplayName 'ZKVPN server {n}' -Group {FW_GROUP} -Direction Outbound "
            f"-Action Allow -Protocol UDP -RemoteAddress {ps_quote(str(addr))} -RemotePort {int(port)} | Out-Null")
    lines.append("Set-NetFirewallProfile -All -DefaultOutboundAction Block")
    return "; ".join(lines)


def killswitch_disable_script(previous: Dict[str, str]) -> str:
    """Restore each profile's outbound default, then remove our rules."""
    parts = []
    for profile, action in previous.items():
        action = "Block" if str(action).lower() in ("block", "2") else "Allow"
        parts.append(f"Set-NetFirewallProfile -Name {ps_quote(check_name(profile))} -DefaultOutboundAction {action}")
    if not parts:
        parts.append("Set-NetFirewallProfile -All -DefaultOutboundAction Allow")
    parts.append(f"Remove-NetFirewallRule -Group {FW_GROUP} -ErrorAction SilentlyContinue")
    return "; ".join(parts)


def parse_firewall_profiles(output: str) -> Dict[str, str]:
    """``{profile: DefaultOutboundAction}`` from ``Get-NetFirewallProfile | ConvertTo-Json``."""
    try:
        data = json.loads(output)
    except ValueError:
        return {}
    if isinstance(data, dict):
        data = [data]
    return {str(p["Name"]): str(p["DefaultOutboundAction"]) for p in data
            if "Name" in p and "DefaultOutboundAction" in p}


def dns_block_script(alias: str, other_aliases: Sequence[str]) -> str:
    others = ",".join(ps_quote(check_name(a)) for a in other_aliases)
    if not others:
        return "$null"
    return "; ".join(
        f"New-NetFirewallRule -DisplayName 'ZKVPN block dns {proto}' -Group {FW_DNS_GROUP} "
        f"-Direction Outbound -Action Block -Protocol {proto} -RemotePort 53,853 "
        f"-InterfaceAlias {others} | Out-Null"
        for proto in ("UDP", "TCP"))


# --------------------------------------------------------------------------- components

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


class WindowsInterface(WireGuardInterface):
    """WireGuard through the official Windows tunnel service (``wireguard.exe /installtunnelservice``)."""

    async def _create_link(self) -> None:
        check_name(self.interface)
        rc, _, _ = await run("wg", "show", self.interface)
        if rc == 0:
            return                                           # tunnel service already running
        exe = wireguard_exe()
        if not exe:
            raise RuntimeError("WireGuard for Windows not found: winget install WireGuard.WireGuard")
        ensure_private_dir(settings.state_dir)
        conf = _state(f"{self.interface}.conf")
        # the tunnel service runs as SYSTEM and reads this file once; it is deleted right after
        write_private_file(conf, tunnel_config(self.private_key, self.listen_port), allow_system=True)
        try:
            rc, out, err = await run(exe, "/installtunnelservice", str(conf), timeout=60)
            if rc != 0 and "already installed" not in (err or out):   # a previous one may still be stopping
                raise RuntimeError(f"installtunnelservice failed: {(err or out).strip()}")
            for _ in range(100):                             # wait for the service to be up
                if (await run("wg", "show", self.interface))[0] == 0:
                    break
                await asyncio.sleep(0.2)
            else:
                raise RuntimeError("the WireGuard tunnel service did not start")
        finally:
            conf.unlink(missing_ok=True)
        logger.info(f"Created tunnel service {self.interface}")

    async def _apply_settings(self) -> None:
        return None                                          # key and port are in the tunnel configuration

    async def bring_up(self) -> None:
        return None                                          # the tunnel service keeps the adapter up

    async def _assign_address(self, address: str) -> None:
        ifc = ipaddress.ip_interface(address)
        last = ""
        for _ in range(50):                                  # the adapter can appear a moment late
            rc, out, err = await run("netsh", "interface", "ip", "set", "address",
                                     f"name={self.interface}", "static",
                                     str(ifc.ip), str(ifc.network.netmask))
            if rc == 0:
                return
            last = (err or out).strip()
            await asyncio.sleep(0.3)
        raise RuntimeError(f"netsh could not set the address: {last}")

    async def _remove_link(self) -> None:
        exe = wireguard_exe()
        if not exe:
            raise RuntimeError("wireguard.exe not found")
        if (await run("wg", "show", check_name(self.interface)))[0] != 0:
            return                                           # already gone: removing twice is fine
        rc, out, err = await run(exe, "/uninstalltunnelservice", self.interface, timeout=60)
        if rc != 0 and "does not exist" not in (err or out):
            raise RuntimeError(f"uninstalltunnelservice failed: {(err or out).strip()}")
        for _ in range(100):                                 # the service takes a moment to disappear
            if (await run("wg", "show", self.interface))[0] != 0:
                return
            await asyncio.sleep(0.2)
        raise RuntimeError("the WireGuard tunnel service did not stop")


class WindowsRouteManager:
    """All traffic through the tunnel: two /1 routes plus a pinned host route to the server."""

    def __init__(self, interface: str):
        self.interface = interface

    async def enable(self, endpoint_ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(endpoint_ip)
        except ValueError:
            logger.error(f"Routes not installed: endpoint {endpoint_ip!r} is not an IP address")
            return False
        rc, out, _ = await powershell(
            f"Find-NetRoute -RemoteIPAddress {ps_quote(endpoint_ip)} | "
            "Where-Object { $_.DestinationPrefix } | Select-Object -First 1 InterfaceIndex,NextHop | "
            "ConvertTo-Json -Compress")
        index, hop = parse_find_netroute(out)
        if rc != 0 or index is None:
            logger.error("Routes not installed: no route to the VPN server")
            return False
        none = "::" if addr.version == 6 else "0.0.0.0"
        prefix = f"{endpoint_ip}/{128 if addr.version == 6 else 32}"
        _save("routes.json", {"endpoint_prefix": prefix})
        script = [new_route_script(prefix, hop or none, index=index)]
        script += [new_route_script(p, "0.0.0.0", alias=self.interface) for p in ("0.0.0.0/1", "128.0.0.0/1")]
        if (await powershell("; ".join(script)))[0] != 0:
            await self.disable()
            logger.error("Routes not installed")
            return False
        for p in ("::/1", "8000::/1"):                       # IPv6 must not bypass the tunnel (best effort)
            await powershell(new_route_script(p, "::", alias=self.interface))
        return True

    async def disable(self) -> None:
        prefixes = ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]
        endpoint = _load("routes.json").get("endpoint_prefix")
        if endpoint:
            prefixes.append(endpoint)
        await powershell("; ".join(remove_route_script(p) for p in prefixes))
        _clear("routes.json")


class WindowsKillSwitch:
    """Block everything but the tunnel and the WireGuard server (Windows Firewall)."""

    def __init__(self, interface: str):
        self.interface = interface
        self.active = False

    async def enable(self, endpoints: Sequence[str]) -> bool:
        try:
            script = killswitch_enable_script(self.interface, endpoints)
        except ValueError as e:
            logger.error(f"Kill-switch not enabled: {e}")
            return False
        _, out, _ = await powershell("Get-NetFirewallProfile | Select-Object Name,DefaultOutboundAction | "
                                     "ConvertTo-Json -Compress")
        _save("killswitch.json", {"previous": parse_firewall_profiles(out)})   # BEFORE changing anything
        rc, _, err = await powershell(script)
        if rc != 0:
            logger.error(f"Kill-switch rules failed: {err.strip()}")
            await self.disable()
            return False
        self.active = True
        return True

    async def disable(self) -> None:
        previous = _load("killswitch.json").get("previous", {})
        await powershell(killswitch_disable_script(previous))
        _clear("killswitch.json")
        self.active = False


class WindowsDNSProtector(DNSProtector):
    """DNS through the tunnel adapter (low metric); plain DNS blocked on the other adapters."""

    async def detect_backend(self) -> str:
        return "windows"

    async def _apply(self, backend: str, state: Dict) -> None:
        servers = ",".join(ps_quote(s) for s in self._dns_servers)
        alias = ps_quote(check_name(self.interface))
        rc, _, err = await powershell(
            f"Set-DnsClientServerAddress -InterfaceAlias {alias} -ServerAddresses ({servers}); "
            f"Set-NetIPInterface -InterfaceAlias {alias} -InterfaceMetric 1; Clear-DnsClientCache")
        if rc != 0:
            raise RuntimeError(f"could not set the tunnel DNS: {err.strip()}")

    async def _revert(self, state: Dict) -> None:
        # the tunnel adapter disappears with the tunnel; nothing else was modified
        await powershell(f"Set-DnsClientServerAddress -InterfaceAlias {ps_quote(check_name(state['interface']))} "
                         "-ResetServerAddresses -ErrorAction SilentlyContinue; Clear-DnsClientCache")

    async def _block_dns_leaks(self) -> None:
        rc, out, _ = await powershell(f"(Get-NetAdapter | Where-Object {{ $_.Name -ne {ps_quote(self.interface)} }})"
                                      ".Name | ConvertTo-Json -Compress")
        try:
            others = json.loads(out) if out.strip() else []
        except ValueError:
            others = []
        others = [others] if isinstance(others, str) else others
        rc, _, err = await powershell(dns_block_script(self.interface, others))
        if rc != 0:
            raise RuntimeError(f"could not install the DNS firewall rules: {err.strip()}")

    async def _remove_dns_blocks(self) -> None:
        await powershell(f"Remove-NetFirewallRule -Group {FW_DNS_GROUP} -ErrorAction SilentlyContinue")

    async def _get_current_dns_servers(self) -> List[str]:
        _, out, _ = await powershell("Get-DnsClientServerAddress -AddressFamily IPv4 | "
                                     "ForEach-Object { $_.ServerAddresses } | ConvertTo-Json -Compress")
        try:
            data = json.loads(out) if out.strip() else []
        except ValueError:
            return []
        return [data] if isinstance(data, str) else list(data)

    async def _check_ipv6(self) -> bool:
        alias = ps_quote(check_name(self.interface))
        _, out, _ = await powershell(
            "(Get-NetIPAddress -AddressFamily IPv6 | Where-Object { $_.IPAddress -notlike 'fe80*' -and "
            f"$_.IPAddress -ne '::1' -and $_.InterfaceAlias -ne {alias} }} | Measure-Object).Count")
        return out.strip().isdigit() and int(out.strip()) > 0


def make_backend() -> NetBackend:
    missing = feature_missing("server role", "Windows")
    return NetBackend(
        name="Windows",
        features=frozenset({CLIENT, ROUTES, KILLSWITCH, DNS}),
        make_interface=WindowsInterface,
        make_routes=WindowsRouteManager,
        make_killswitch=WindowsKillSwitch,
        make_dns=WindowsDNSProtector,
        make_nat=missing,
        notes="client role; needs WireGuard for Windows and an elevated terminal; kill-switch experimental",
    )
