"""Linux backend: iproute2, WireGuard (kernel or wireguard-go), iptables/ip6tables, resolver backends.

This is the reference implementation, exercised end to end by ``tests/e2e``.
"""

from zkvpn.platform.net.base import (CLIENT, DNS, KILLSWITCH, ROUTES, SERVER, NetBackend)


def make_backend() -> NetBackend:
    # imported lazily: these modules import settings, which imports the platform package
    from zkvpn.protocol.dns import DNSProtector
    from zkvpn.protocol.killswitch import KillSwitch
    from zkvpn.protocol.routing import RouteManager, ServerNAT
    from zkvpn.protocol.wireguard import WireGuardInterface

    return NetBackend(
        name="Linux",
        features=frozenset({CLIENT, ROUTES, KILLSWITCH, DNS, SERVER}),
        make_interface=WireGuardInterface,
        make_routes=RouteManager,
        make_killswitch=KillSwitch,
        make_dns=DNSProtector,
        make_nat=ServerNAT,
        notes="verified end to end (network namespaces, real systemd)",
    )
