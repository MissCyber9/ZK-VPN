"""Tests for the real Groth16 session-auth proofs (need `scripts/setup_circuits.sh`)."""

import copy

import pytest

from zkvpn.zk import (SessionProver, SessionVerifier, SnarkBackend, SnarkError,
                      generate_identity)

backend = SnarkBackend()
pytestmark = pytest.mark.skipif(
    not backend.available, reason="run scripts/setup_circuits.sh first")

WG = "A" * 43 + "="
OTHER_WG = "B" * 43 + "="


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def env():
    clock = Clock()
    return (clock, SessionProver(backend, clock), SessionVerifier(backend, clock=clock),
            generate_identity())


async def test_valid_proof_accepted(env):
    clock, prover, verifier, sk = env
    nonce = verifier.issue_challenge()
    proof = await prover.prove(sk, nonce, WG)
    result = await verifier.verify(proof, nonce, WG)
    assert result.valid, result.error
    assert result.pk == str(proof.pk)


async def test_replay_rejected(env):
    clock, prover, verifier, sk = env
    nonce = verifier.issue_challenge()
    proof = await prover.prove(sk, nonce, WG)
    assert (await verifier.verify(proof, nonce, WG)).valid
    assert not (await verifier.verify(proof, nonce, WG)).valid


async def test_proof_bound_to_wireguard_key(env):
    clock, prover, verifier, sk = env
    nonce = verifier.issue_challenge()
    proof = await prover.prove(sk, nonce, WG)
    result = await verifier.verify(proof, nonce, OTHER_WG)
    assert not result.valid and "mismatch" in result.error


async def test_tampered_signal_rejected(env):
    clock, prover, verifier, sk = env
    nonce = verifier.issue_challenge()
    proof = await prover.prove(sk, nonce, WG)
    forged = copy.deepcopy(proof)
    forged.public_signals[0] = str(int(forged.public_signals[0]) + 1)  # claim another pk
    result = await verifier.verify(forged, nonce, WG)
    assert not result.valid and result.error == "invalid proof"


async def test_garbage_proof_rejected(env):
    clock, prover, verifier, sk = env
    nonce = verifier.issue_challenge()
    proof = await prover.prove(sk, nonce, WG)
    proof.proof = {"pi_a": ["1", "2", "1"], "pi_b": [], "pi_c": [], "protocol": "groth16"}
    assert not (await verifier.verify(proof, nonce, WG)).valid


async def test_unissued_and_expired_challenge(env):
    clock, prover, verifier, sk = env
    proof = await prover.prove(sk, "deadbeef", WG)
    assert not (await verifier.verify(proof, "deadbeef", WG)).valid
    nonce = verifier.issue_challenge()
    proof = await prover.prove(sk, nonce, WG)
    clock.t += 120
    assert not (await verifier.verify(proof, nonce, WG)).valid


async def test_stale_timestamp_cannot_be_proven(env):
    clock, prover, verifier, sk = env
    nonce = verifier.issue_challenge()
    with pytest.raises(SnarkError):
        await prover.prove(sk, nonce, WG, timestamp=int(clock.t) - 1000)


async def test_future_timestamp_cannot_be_proven(env):
    clock, prover, verifier, sk = env
    nonce = verifier.issue_challenge()
    with pytest.raises(SnarkError):
        await prover.prove(sk, nonce, WG, timestamp=int(clock.t) + 10)


async def test_unauthorized_identity_rejected():
    clock = Clock()
    prover = SessionProver(backend, clock)
    verifier = SessionVerifier(backend, authorized=["12345"], clock=clock)
    nonce = verifier.issue_challenge()
    proof = await prover.prove(generate_identity(), nonce, WG)
    result = await verifier.verify(proof, nonce, WG)
    assert not result.valid and "not authorized" in result.error


async def test_authorized_identity_and_proof_chain(env):
    clock, prover, _, sk = env
    first_nonce_verifier = SessionVerifier(backend, clock=clock)
    n1 = first_nonce_verifier.issue_challenge()
    p1 = await prover.prove(sk, n1, WG)
    r1 = await first_nonce_verifier.verify(p1, n1, WG)
    assert r1.valid
    # An authorized-list verifier built from the observed identity accepts it.
    verifier = SessionVerifier(backend, authorized=[r1.pk], clock=clock)
    n2 = verifier.issue_challenge()
    assert (await verifier.verify(await prover.prove(sk, n2, WG), n2, WG)).valid
    # Next proof must extend the chain with the previous tag.
    n3 = verifier.issue_challenge()
    bad = await prover.prove(sk, n3, WG, prev_tag=0)
    assert "prev_tag" in (await verifier.verify(bad, n3, WG)).error
    n4 = verifier.issue_challenge()
    good = await prover.prove(sk, n4, WG, prev_tag=verifier._last_tag[r1.pk])
    assert (await verifier.verify(good, n4, WG)).valid


async def test_tunnel_admits_client_with_real_proof():
    from unittest.mock import AsyncMock, patch
    from zkvpn.protocol.tunnel import ZKTunnel
    from zkvpn.protocol.wireguard import WireGuardInterface

    tunnel = ZKTunnel()
    prover = SessionProver(backend)
    nonce = tunnel.issue_challenge()
    proof = await prover.prove(generate_identity(), nonce, WG)

    with patch.object(WireGuardInterface, "add_peer", AsyncMock(return_value=True)) as add_peer, \
         patch.object(tunnel, "_assign_client_ip", AsyncMock(return_value="10.0.0.10")):
        # proof made for WG key `WG` must not admit `OTHER_WG`
        assert await tunnel.add_client(OTHER_WG, nonce=nonce, proof=proof) is False
        add_peer.assert_not_called()
        assert await tunnel.add_client(WG, nonce=nonce, proof=proof) is True
        add_peer.assert_called_once()
