"""Session authentication with Groth16 proofs (circuit: ``session_auth.circom``).

Protocol
--------
1. The server calls ``SessionVerifier.issue_challenge()`` -> random ``nonce``.
2. The client computes ``challenge = bind_challenge(nonce, wireguard_public_key)``
   and proves knowledge of its secret ``sk`` (``SessionProver.prove``).
3. The server calls ``SessionVerifier.verify(proof, nonce, wireguard_public_key)``.

What a valid proof establishes: the prover knows the secret key behind identity
``pk``; the proof was made for this server challenge *and this WireGuard key*
(no replay, no transplanting onto another key); and its timestamp is fresh.
Optionally (``enforce_chain``) it also extends the identity's previous proof.

It does not, and cannot, prove that the server keeps no logs.
"""

import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional

from zkvpn.zk.snark import SnarkBackend, SnarkError

# bn128 scalar field
FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617
MAX_DRIFT = 300  # must match SessionAuth(300) in the circuit
# Public signal order: outputs first, then public inputs.
_SIGNALS = ("pk", "tag", "challenge", "timestamp", "current_time", "prev_tag")


def generate_identity() -> int:
    """Random secret key in the field (keep it secret, never log it)."""
    return secrets.randbelow(FIELD_PRIME - 1) + 1


def bind_challenge(nonce: str, wireguard_public_key: str) -> int:
    """Challenge field element bound to both the server nonce and the WG key."""
    digest = hashlib.sha256(f"zkvpn-v1|{nonce}|{wireguard_public_key}".encode()).digest()
    return int.from_bytes(digest, "big") % FIELD_PRIME


@dataclass
class SessionProof:
    proof: Dict
    public_signals: List[str]

    def __getattr__(self, name):  # pk, tag, challenge, ... as ints
        if name in _SIGNALS:
            return int(self.public_signals[_SIGNALS.index(name)])
        raise AttributeError(name)


@dataclass
class VerifyResult:
    valid: bool
    error: Optional[str] = None
    pk: Optional[str] = None


class SessionProver:
    def __init__(self, backend: Optional[SnarkBackend] = None,
                 clock: Callable[[], float] = time.time):
        self.backend = backend or SnarkBackend()
        self._clock = clock

    async def prove(self, sk: int, nonce: str, wireguard_public_key: str,
                    prev_tag: int = 0, timestamp: Optional[int] = None) -> SessionProof:
        now = int(self._clock())
        inputs = {
            "sk": str(sk),
            "challenge": str(bind_challenge(nonce, wireguard_public_key)),
            "timestamp": str(now if timestamp is None else timestamp),
            "current_time": str(now),
            "prev_tag": str(prev_tag),
        }
        proof, signals = await self.backend.prove(inputs)
        return SessionProof(proof, signals)


class SessionVerifier:
    """Server side: issues challenges, verifies proofs, tracks per-identity chains."""

    def __init__(self, backend: Optional[SnarkBackend] = None,
                 authorized: Optional[Iterable[str]] = None,
                 challenge_ttl: float = 60.0, clock_tolerance: float = 30.0,
                 enforce_chain: bool = False,
                 clock: Callable[[], float] = time.time):
        self.backend = backend or SnarkBackend()
        self.authorized = {str(a) for a in authorized} if authorized else None
        self.challenge_ttl = challenge_ttl
        self.clock_tolerance = clock_tolerance
        # Replay is already prevented by single-use, key-bound challenges. Enforcing
        # the prev_tag chain additionally requires clients to persist their last tag
        # (and the server its state across restarts), so it is opt-in.
        self.enforce_chain = enforce_chain
        self._clock = clock
        self._challenges: Dict[str, float] = {}   # nonce -> expiry
        self._last_tag: Dict[str, int] = {}       # pk -> last accepted tag

    def issue_challenge(self) -> str:
        now = self._clock()
        self._challenges = {n: e for n, e in self._challenges.items() if e > now}
        nonce = secrets.token_hex(16)
        self._challenges[nonce] = now + self.challenge_ttl
        return nonce

    def _fail(self, msg: str) -> VerifyResult:
        return VerifyResult(False, msg)

    async def verify(self, proof: SessionProof, nonce: str,
                     wireguard_public_key: str) -> VerifyResult:
        # Cheap, non-cryptographic checks first.
        signals = proof.public_signals
        if len(signals) != len(_SIGNALS) or not all(
                isinstance(s, str) and s.isdigit() for s in signals):
            return self._fail("malformed public signals")
        now = self._clock()
        expiry = self._challenges.get(nonce)
        if expiry is None or expiry <= now:
            return self._fail("unknown, used or expired challenge")
        if proof.challenge != bind_challenge(nonce, wireguard_public_key):
            return self._fail("challenge mismatch")
        if abs(proof.current_time - now) > self.clock_tolerance:
            return self._fail("proof clock out of tolerance")
        if not 0 <= proof.current_time - proof.timestamp <= MAX_DRIFT:
            return self._fail("stale timestamp")
        pk = str(proof.pk)
        if self.authorized is not None and pk not in self.authorized:
            return self._fail("identity not authorized")
        if self.enforce_chain and proof.prev_tag != self._last_tag.get(pk, 0):
            return self._fail("prev_tag does not extend the proof chain")

        try:
            ok = await self.backend.verify(proof.proof, signals)
        except SnarkError as e:
            return self._fail(f"verifier unavailable: {e}")
        if not ok:
            return self._fail("invalid proof")

        # Single use: consume the challenge and advance the chain only on success.
        self._challenges.pop(nonce, None)
        self._last_tag[pk] = proof.tag
        return VerifyResult(True, pk=pk)
