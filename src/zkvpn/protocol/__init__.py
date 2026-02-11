"""ZK-VPN protocol package.

WireGuard integration with zero-knowledge proof authentication.
"""

from zkvpn.protocol.wireguard import WireGuardInterface, WireGuardPeer, wg_interface
from zkvpn.protocol.tunnel import ZKTunnel, TunnelConfig, tunnel
from zkvpn.protocol.dns import DNSProtector, dns_protector

__all__ = [
    "WireGuardInterface",
    "WireGuardPeer",
    "wg_interface",
    "ZKTunnel",
    "TunnelConfig",
    "tunnel",
    "DNSProtector",
    "dns_protector"
]
