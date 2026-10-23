"""Interface every operating-system network backend implements."""

from dataclasses import dataclass, field
from typing import Any, Callable, FrozenSet

from zkvpn.platform import UnsupportedPlatform

# What a backend may provide
CLIENT = "client"          # create the tunnel interface, addresses, peers
ROUTES = "routes"          # send all traffic through the tunnel
KILLSWITCH = "killswitch"  # block traffic outside the tunnel
DNS = "dns"                # DNS through the tunnel
SERVER = "server"          # accept clients (forwarding, NAT, client isolation)
FEATURES = (CLIENT, ROUTES, KILLSWITCH, DNS, SERVER)


@dataclass(frozen=True)
class NetBackend:
    """The OS-specific parts of ZK-VPN, as factories.

    Components share one duck-typed interface (see the Linux implementations):

    * interface:  ``generate_keypair, configure_interface, add_peer, remove_peer, get_status,
                  set_address, delete_interface, is_initialized, interface, public_key, address``
    * routes:     ``enable(endpoint_ip) -> bool, disable()``
    * killswitch: ``enable(endpoints) -> bool, disable(), active``
    * nat:        ``enable() -> bool, disable(), active``
    * dns:        ``enable_protection(), disable_protection(), is_protected, test_leaks()``

    ``interface`` may be renamed by the OS when it is created (macOS ``utunN``); the tunnel
    refreshes the ``interface`` attribute of the other components afterwards.
    """

    name: str
    features: FrozenSet[str]
    make_interface: Callable[[str], Any]
    make_routes: Callable[[str], Any]
    make_killswitch: Callable[[str], Any]
    make_dns: Callable[[str], Any]
    make_nat: Callable[[str, str], Any]
    notes: str = ""

    def supports(self, feature: str) -> bool:
        return feature in self.features


def _unsupported(message: str):
    def factory(*_args, **_kwargs):
        raise UnsupportedPlatform(message)
    return factory


def unsupported_backend(name: str) -> NetBackend:
    """Backend for an unknown OS: the portable commands (identity, zk, doctor) still work."""
    fail = _unsupported(f"No network support for {name!r}. Supported: Linux, macOS, Windows.")
    return NetBackend(name=name, features=frozenset(), make_interface=fail, make_routes=fail,
                      make_killswitch=fail, make_dns=fail, make_nat=fail,
                      notes="unsupported operating system")


def feature_missing(feature: str, system_name: str):
    """Factory for a feature a backend does not implement (clear error instead of a crash)."""
    def factory(*_args, **_kwargs):
        raise UnsupportedPlatform(f"{feature!r} is not available on {system_name}")
    return factory
