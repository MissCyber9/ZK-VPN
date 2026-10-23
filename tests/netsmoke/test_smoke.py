"""Real WireGuard interfaces on macOS and Windows (run by CI on real runners; needs admin + WireGuard).

Two interfaces are created on the same machine and made to talk to each other over loopback:
that exercises interface creation (wireguard-go / the Windows tunnel service), key loading,
addressing, peers, the handshake, `wg show` parsing and deletion. Routes, firewall and DNS are
deliberately NOT touched here: applying them to a CI runner would cut the runner's own connection.

    macOS:    sudo -E $(which python) -m pytest -m netsmoke tests/netsmoke
    Windows:  python -m pytest -m netsmoke tests/netsmoke     (elevated terminal)
"""

import shutil
import socket
import sys
import time

import pytest

from zkvpn.diagnostics import is_privileged
from zkvpn.platform.net import backend
from zkvpn.protocol.wireguard import WireGuardPeer

pytestmark = [pytest.mark.netsmoke]
if sys.platform not in ("darwin", "win32"):
    pytestmark.append(pytest.mark.skip(reason="macOS and Windows only"))
elif not shutil.which("wg"):
    pytestmark.append(pytest.mark.skip(reason="wg not installed"))
elif not is_privileged():
    pytestmark.append(pytest.mark.skip(reason="needs root / an elevated terminal"))

PORT_A, PORT_B = 51831, 51832


@pytest.fixture
async def pair(tmp_path, monkeypatch):
    from zkvpn.core.config import settings
    monkeypatch.setattr(settings, "state_dir", str(tmp_path / "state"))
    a, b = backend.make_interface("zkvpn-a"), backend.make_interface("zkvpn-b")
    a.listen_port, b.listen_port = PORT_A, PORT_B
    try:
        assert await a.configure_interface() is True
        assert await b.configure_interface() is True
        yield a, b
    finally:
        await b.delete_interface()
        await a.delete_interface()


async def wait_for_handshake(iface, seconds=20):
    end = time.time() + seconds
    while time.time() < end:
        peers = (await iface.get_status()).get("peers", [])
        if peers and peers[0].get("latest_handshake"):
            return peers[0]
        await _nudge()
        time.sleep(0.5)
    raise AssertionError(f"no handshake on {iface.interface}: {await iface.get_status()}")


async def _nudge():
    # a packet towards the peer's tunnel address makes the OS route it into the tunnel
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.sendto(b"zkvpn", ("10.99.0.1", 9))
        except OSError:
            pass


async def test_interfaces_exist_and_report_their_keys(pair):
    a, b = pair
    for iface in pair:
        status = await iface.get_status()
        assert "error" not in status, status
        assert status["public_key"] == iface.public_key
    assert a.public_key != b.public_key


async def test_two_interfaces_complete_a_handshake_over_loopback(pair):
    a, b = pair
    assert await b.set_address("10.99.0.2/24") is True
    assert await a.add_peer(WireGuardPeer(public_key=b.public_key, allowed_ips=["10.99.0.2/32"]))
    assert await b.add_peer(WireGuardPeer(public_key=a.public_key, endpoint=f"127.0.0.1:{PORT_A}",
                                          allowed_ips=["10.99.0.1/32"], persistent_keepalive=1))
    peer = await wait_for_handshake(b)
    assert peer["public_key"] == a.public_key
    assert peer["endpoint"] == f"127.0.0.1:{PORT_A}"
    assert peer["allowed_ips"] == ["10.99.0.1/32"]
    assert (await wait_for_handshake(a))["public_key"] == b.public_key      # both ends agree


async def test_deleting_an_interface_removes_it(pair):
    a, _ = pair
    name = a.interface
    assert await a.delete_interface() is True
    time.sleep(1)
    status = await backend.make_interface(name).get_status()
    assert "error" in status                                            # `wg show` no longer finds it
