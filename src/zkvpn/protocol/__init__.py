"""ZK-VPN protocol package.

WireGuard integration with zero-knowledge proof authentication.

Only classes are exported here. The module-level instances (``tunnel``, ``wg_interface``...)
are deliberately NOT re-exported: a package attribute named ``tunnel`` or ``killswitch`` would
shadow the submodule of the same name (breaking ``unittest.mock.patch`` on older Pythons).
Import them from their module, e.g. ``from zkvpn.protocol.tunnel import tunnel``.
"""

from zkvpn.protocol.wireguard import WireGuardInterface, WireGuardPeer
from zkvpn.protocol.tunnel import ZKTunnel, TunnelConfig
from zkvpn.protocol.dns import DNSProtector
from zkvpn.protocol.killswitch import KillSwitch

__all__ = [
    "WireGuardInterface",
    "WireGuardPeer",
    "ZKTunnel",
    "TunnelConfig",
    "DNSProtector",
    "KillSwitch",
]
