"""Admission protocol: how a client proves itself to a server before joining.

A short TCP exchange of JSON lines (all fields are public data; no secret ever
crosses the wire, so no transport encryption is needed for confidentiality):

    client -> {"type": "hello", "wg_public_key": "<44-char base64>"}
    server -> {"type": "challenge", "nonce": "<hex>"}
    client -> {"type": "proof", "proof": {...}, "public_signals": [...]}
    server -> {"type": "ok", "client_ip": "10.0.0.2"}  |  {"type": "error", "reason": "..."}

The proof is bound to the nonce *and* the WireGuard key from the hello, so a
man in the middle can neither replay it nor substitute their own key.
The client must already know the server's WireGuard public key out of band
(it is what authenticates the server); the admission channel does not.
"""

import asyncio
import json
import logging
from typing import Any, Dict, Optional

from zkvpn.core.config import settings
from zkvpn.protocol.wireguard import validate_public_key
from zkvpn.zk import SessionProof, SessionProver

logger = logging.getLogger(__name__)

MAX_MESSAGE_BYTES = 64 * 1024
HELLO_TIMEOUT = 5.0     # a client must speak quickly...
PROOF_TIMEOUT = 30.0    # ...but generating a proof can take seconds on slow devices


class AdmissionError(RuntimeError):
    """The server refused (or could not complete) the admission."""


async def _send(writer: asyncio.StreamWriter, msg: Dict[str, Any]) -> None:
    writer.write(json.dumps(msg).encode() + b"\n")
    await writer.drain()


async def _recv(reader: asyncio.StreamReader, timeout: float) -> Dict[str, Any]:
    line = await asyncio.wait_for(reader.readline(), timeout)
    if not line:
        raise AdmissionError("connection closed")
    msg = json.loads(line)
    if not isinstance(msg, dict):
        raise ValueError("message must be an object")
    return msg


class AdmissionServer:
    """Accepts clients on ``port`` and admits them into the tunnel after a ZK proof."""

    def __init__(self, tunnel, host: Optional[str] = None, port: Optional[int] = None,
                 max_verifications: int = 4, max_connections: int = 64,
                 max_per_ip: int = 4, hello_timeout: float = HELLO_TIMEOUT,
                 proof_timeout: float = PROOF_TIMEOUT):
        self.tunnel = tunnel
        self.host = host or settings.host
        self.port = port if port is not None else settings.admission_port
        self.hello_timeout = hello_timeout
        self.proof_timeout = proof_timeout
        self.max_connections = max_connections
        self.max_per_ip = max_per_ip
        # Verification is CPU-heavy: bound it, but never hold a slot while merely
        # waiting on a (possibly malicious) slow client.
        self._verify_slots = asyncio.Semaphore(max_verifications)
        self._per_ip: Dict[str, int] = {}
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, self.host, self.port, limit=MAX_MESSAGE_BYTES)
        sock = self._server.sockets[0].getsockname()
        self.port = sock[1]
        logger.info(f"Admission server listening on {sock[0]}:{sock[1]}")

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        peer = (writer.get_extra_info("peername") or ("?",))[0]
        if sum(self._per_ip.values()) >= self.max_connections \
                or self._per_ip.get(peer, 0) >= self.max_per_ip:
            logger.info("Admission attempt dropped: too many connections")
            writer.close()
            return
        self._per_ip[peer] = self._per_ip.get(peer, 0) + 1
        try:
            await self._admit(reader, writer)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError,
                ValueError, KeyError, TypeError, AdmissionError) as e:
            logger.info(f"Admission attempt dropped: {type(e).__name__}")
            try:
                await _send(writer, {"type": "error", "reason": "bad request"})
            except Exception:
                pass
        finally:
            self._per_ip[peer] -= 1
            if not self._per_ip[peer]:
                del self._per_ip[peer]
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _admit(self, reader, writer) -> None:
        hello = await _recv(reader, self.hello_timeout)
        if hello.get("type") != "hello":
            raise ValueError("expected hello")
        wg_key = validate_public_key(hello["wg_public_key"])

        nonce = self.tunnel.issue_challenge()
        await _send(writer, {"type": "challenge", "nonce": nonce})

        msg = await _recv(reader, self.proof_timeout)
        if msg.get("type") != "proof":
            raise ValueError("expected proof")
        signals = msg["public_signals"]
        if not isinstance(signals, list) or not isinstance(msg["proof"], dict):
            raise ValueError("malformed proof")
        proof = SessionProof(msg["proof"], [str(s) for s in signals])

        async with self._verify_slots:
            admitted = await self.tunnel.add_client(wg_key, nonce=nonce, proof=proof)
        if not admitted:
            # Deliberately generic: do not tell an attacker which check failed.
            await _send(writer, {"type": "error", "reason": "admission refused"})
            return
        await _send(writer, {"type": "ok", "client_ip": self.tunnel.client_ips[wg_key]})


async def request_admission(host: str, port: int, wg_public_key: str, sk: int,
                            prover: Optional[SessionProver] = None,
                            timeout: float = 30.0) -> str:
    """Run the client side; returns the tunnel IP assigned by the server."""
    prover = prover or SessionProver()
    validate_public_key(wg_public_key)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, limit=MAX_MESSAGE_BYTES), timeout)
    except (OSError, asyncio.TimeoutError) as e:
        raise AdmissionError(f"cannot reach admission server: {e}")
    try:
        await _send(writer, {"type": "hello", "wg_public_key": wg_public_key})
        challenge = await _recv(reader, timeout)
        if challenge.get("type") != "challenge":
            raise AdmissionError("server refused")
        proof = await prover.prove(sk, challenge["nonce"], wg_public_key)
        await _send(writer, {"type": "proof", "proof": proof.proof,
                             "public_signals": proof.public_signals})
        result = await _recv(reader, timeout)
        if result.get("type") != "ok":
            raise AdmissionError(result.get("reason", "admission refused"))
        return result["client_ip"]
    except (asyncio.TimeoutError, json.JSONDecodeError, KeyError) as e:
        raise AdmissionError(f"admission failed: {type(e).__name__}")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


__all__ = ["AdmissionServer", "AdmissionError", "request_admission"]
