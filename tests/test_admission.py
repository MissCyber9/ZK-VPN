"""End-to-end admission over a real TCP socket with real Groth16 proofs."""

import asyncio
import json
import os
import stat
from unittest.mock import AsyncMock, patch

import pytest

from zkvpn.protocol.admission import AdmissionError, AdmissionServer, request_admission
from zkvpn.protocol.tunnel import ZKTunnel
from zkvpn.protocol.wireguard import WireGuardInterface
from zkvpn.zk import (SnarkBackend, generate_identity, load_identity, save_identity)
from zkvpn.platform.net import get_backend

LINUX = get_backend("linux")      # these tests exercise the Linux server role on any runner

needs_zk = pytest.mark.skipif(not SnarkBackend().available,
                              reason="run `zkvpn zk setup` first")

WG1 = "A" * 43 + "="
WG2 = "B" * 43 + "="


@pytest.fixture
async def server():
    tunnel = ZKTunnel(backend=LINUX)
    ips = iter(["10.0.0.2", "10.0.0.3", "10.0.0.4"])
    with patch.object(WireGuardInterface, "add_peer", AsyncMock(return_value=True)), \
         patch.object(tunnel, "_assign_client_ip", AsyncMock(side_effect=lambda: next(ips))):
        srv = AdmissionServer(tunnel, host="127.0.0.1", port=0,
                              hello_timeout=2, proof_timeout=15, max_per_ip=50)
        await srv.start()
        yield tunnel, srv
        await srv.stop()


@needs_zk
async def test_client_is_admitted_and_gets_ip(server):
    tunnel, srv = server
    ip = await request_admission("127.0.0.1", srv.port, WG1, generate_identity())
    assert ip == "10.0.0.2"
    assert tunnel.client_ips[WG1] == "10.0.0.2"


@needs_zk
async def test_same_key_keeps_its_ip(server):
    tunnel, srv = server
    sk = generate_identity()
    first = await request_admission("127.0.0.1", srv.port, WG1, sk)
    second = await request_admission("127.0.0.1", srv.port, WG1, sk)
    assert first == second


@needs_zk
async def test_unauthorized_identity_refused(server):
    tunnel, srv = server
    tunnel.auth.authorized = {"1"}
    with pytest.raises(AdmissionError):
        await request_admission("127.0.0.1", srv.port, WG1, generate_identity())
    assert WG1 not in tunnel.client_ips


async def _talk(port, *messages, read=True):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    out = []
    for m in messages:
        writer.write((m if isinstance(m, bytes) else json.dumps(m).encode()) + b"\n")
        await writer.drain()
        if read:
            out.append(json.loads(await asyncio.wait_for(reader.readline(), 3)))
    writer.close()
    return out


async def test_invalid_proof_refused_without_leaking_reason(server):
    tunnel, srv = server
    hello, result = await _talk(
        srv.port,
        {"type": "hello", "wg_public_key": WG1},
        {"type": "proof", "proof": {"pi_a": []}, "public_signals": ["1"] * 6},
    )
    assert hello["type"] == "challenge"
    assert result == {"type": "error", "reason": "admission refused"}
    assert WG1 not in tunnel.client_ips


@pytest.mark.parametrize("payload", [b"not json", b"[]", b'{"type":"proof"}',
                                     b'{"type":"hello","wg_public_key":"--help"}'])
async def test_garbage_is_rejected(server, payload):
    tunnel, srv = server
    (reply,) = await _talk(srv.port, payload)
    assert reply["type"] == "error"


async def test_oversized_message_dropped(server):
    tunnel, srv = server
    reader, writer = await asyncio.open_connection("127.0.0.1", srv.port)
    writer.write(b"x" * (200 * 1024) + b"\n")
    try:
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(), 3)
        assert reply in (b"", b'{"type": "error", "reason": "bad request"}\n')
    except ConnectionError:
        pass                                  # server dropped us mid-flood: also fine
    writer.close()
    assert WG1 not in tunnel.client_ips


async def test_silent_client_times_out(server):
    tunnel, srv = server
    reader, writer = await asyncio.open_connection("127.0.0.1", srv.port)
    data = await asyncio.wait_for(reader.read(), 5)   # server gives up after step_timeout
    assert b"error" in data
    writer.close()


@needs_zk
async def test_connect_uses_server_assigned_ip(server):
    tunnel, srv = server
    client = ZKTunnel(backend=LINUX)
    client.interface.public_key = WG1
    client.interface._initialized = True
    with patch.object(WireGuardInterface, "add_peer", AsyncMock(return_value=True)), \
         patch.object(WireGuardInterface, "set_address", AsyncMock(return_value=True)) as set_addr, \
         patch.object(client.killswitch, "enable", AsyncMock(return_value=True)), \
         patch.object(client.routes, "enable", AsyncMock(return_value=True)), \
         patch.object(client, "_bring_up", AsyncMock()):
        ok = await client.connect(f"127.0.0.1:51820", WG2,
                                  identity_sk=generate_identity(), admission_port=srv.port)
    assert ok is True
    set_addr.assert_awaited_with("10.0.0.2/24")
    client._health_check_task.cancel()


async def test_connect_fails_closed_when_admission_refused(server):
    tunnel, srv = server
    client = ZKTunnel(backend=LINUX)
    client.interface._initialized = True
    client.interface.public_key = WG1
    with patch.object(WireGuardInterface, "add_peer", AsyncMock()) as add_peer, \
         patch("zkvpn.protocol.tunnel.request_admission",
               AsyncMock(side_effect=AdmissionError("refused"))):
        assert await client.connect("127.0.0.1:51820", WG2, identity_sk=1) is False
    add_peer.assert_not_called()


def test_identity_file_permissions(tmp_path):
    path = str(tmp_path / "id")
    sk = save_identity(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert load_identity(path) == sk
    with pytest.raises(FileExistsError):
        save_identity(path)                      # never overwrite an identity
    os.chmod(path, 0o644)
    with pytest.raises(PermissionError):
        load_identity(path)                      # refuse world-readable secrets


async def test_per_ip_limit_drops_extra_connections(server):
    tunnel, srv = server
    srv.max_per_ip = 2
    held = [await asyncio.open_connection("127.0.0.1", srv.port) for _ in range(2)]
    await asyncio.sleep(0.2)
    reader, writer = await asyncio.open_connection("127.0.0.1", srv.port)
    assert await asyncio.wait_for(reader.read(), 3) == b""      # dropped without a word
    for _, w in held:
        w.close()
    writer.close()
