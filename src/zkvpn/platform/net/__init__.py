"""Per-operating-system network backends.

``backend`` is the one for the machine we run on; ``get_backend(name)`` picks any of them
(used by tests). Unknown systems get a backend with no features, so the portable parts of
the CLI (identity, ZK setup, diagnostics) keep working.
"""

from typing import Optional

from zkvpn.platform import LINUX, MACOS, WINDOWS, UnsupportedPlatform, system
from zkvpn.platform.net.base import (CLIENT, DNS, FEATURES, KILLSWITCH, ROUTES, SERVER,
                                     NetBackend, unsupported_backend)


def get_backend(system_name: Optional[str] = None) -> NetBackend:
    import sys
    try:
        name = system(system_name)
    except UnsupportedPlatform:
        return unsupported_backend(system_name or sys.platform)
    if name == LINUX:
        from zkvpn.platform.net.linux import make_backend
    elif name == MACOS:
        from zkvpn.platform.net.macos import make_backend
    else:
        from zkvpn.platform.net.windows import make_backend
    return make_backend()


class _CurrentBackend:
    """Resolves lazily, so importing the package never touches the OS."""

    _backend: Optional[NetBackend] = None

    def _get(self) -> NetBackend:
        if self._backend is None:
            self._backend = get_backend()
        return self._backend

    def __getattr__(self, item):
        return getattr(self._get(), item)


backend = _CurrentBackend()

__all__ = ["backend", "get_backend", "NetBackend", "FEATURES", "CLIENT", "ROUTES", "KILLSWITCH",
           "DNS", "SERVER"]
