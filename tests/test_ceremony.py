"""Multi-party ceremony: 3 contributors + beacon, verification, real proofs, attacks.

Uses the Python implementation (`zkvpn.zk.ceremony`), so it runs on every OS.
"""

import shutil
import time

import pytest

from zkvpn.zk import SessionProver, SessionVerifier, SnarkBackend, generate_identity
from zkvpn.zk import ceremony as cer
from zkvpn.zk import toolchain
from zkvpn.zk.toolchain import ToolchainError

WG = "A" * 43 + "="
pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(not shutil.which("node") or not shutil.which("npm"), reason="needs Node.js and npm"),
]


class Clock:
    def __call__(self):
        return time.time()


@pytest.fixture(scope="module")
def workspace(tmp_path_factory):
    return toolchain.prepare_workspace(tmp_path_factory.mktemp("ws"))


@pytest.fixture(scope="module")
def ceremony(workspace, tmp_path_factory):
    d = tmp_path_factory.mktemp("ceremony")
    cer.init(d, dev=True, zk_dir=workspace)
    keys = [d / f"zkey_{i:04d}.zkey" for i in range(4)]
    for i, who in enumerate(("Alice", "Bob", "Carol"), start=1):
        cer.contribute(keys[i - 1], keys[i], who, zk_dir=workspace)
    final = d / "zkey_final.zkey"
    cer.beacon(keys[3], final, "0123456789abcdef0123456789abcdef", zk_dir=workspace)
    return {"dir": d, "keys": keys, "final": final, "ws": workspace}


def test_full_chain_verifies_and_lists_all_contributors(ceremony):
    report = cer.verify(ceremony["final"], ceremony["dir"], ceremony["ws"])
    for who in ("Alice", "Bob", "Carol"):
        assert who in report                                  # every contribution is in the chain


def test_untouched_start_of_chain_is_valid(ceremony):
    cer.verify(ceremony["keys"][0], ceremony["dir"], ceremony["ws"])


def test_tampered_zkey_is_rejected(ceremony):
    bad = ceremony["dir"] / "tampered.zkey"
    data = bytearray(ceremony["final"].read_bytes())
    data[len(data) // 2] ^= 0xFF
    bad.write_bytes(bytes(data))
    with pytest.raises(ToolchainError):
        cer.verify(bad, ceremony["dir"], ceremony["ws"])


def test_zkey_from_another_ceremony_is_rejected(ceremony, tmp_path):
    other = tmp_path / "other"
    cer.init(other, dev=True, zk_dir=ceremony["ws"])           # different phase 1 + entropy
    with pytest.raises(ToolchainError):
        cer.verify(other / "zkey_0000.zkey", ceremony["dir"], ceremony["ws"])


def test_bad_beacon_input_rejected(ceremony):
    with pytest.raises(ToolchainError):
        cer.beacon(ceremony["keys"][3], ceremony["dir"] / "x.zkey", "zz", zk_dir=ceremony["ws"])


def test_cannot_reinitialise_or_overwrite(ceremony):
    with pytest.raises(ToolchainError):
        cer.init(ceremony["dir"], dev=True, zk_dir=ceremony["ws"])
    with pytest.raises(ToolchainError):
        cer.contribute(ceremony["keys"][0], ceremony["keys"][1], "again", zk_dir=ceremony["ws"])


async def test_proofs_work_with_ceremony_keys_and_not_with_old_ones(ceremony, tmp_path):
    ws2 = toolchain.prepare_workspace(tmp_path / "ws2")        # a workspace that will use the ceremony keys
    build = cer.finalize(ceremony["final"], ceremony["dir"], ws2)
    assert "ceremony=multi-party" in (build / "CEREMONY.txt").read_text()

    backend = SnarkBackend(zk_dir=str(ws2))
    assert backend.available
    prover, verifier = SessionProver(backend, Clock()), SessionVerifier(backend, clock=Clock())
    nonce = verifier.issue_challenge()
    proof = await prover.prove(generate_identity(), nonce, WG)
    assert (await verifier.verify(proof, nonce, WG)).valid

    # A proof made with other (single-party development) keys must NOT verify under the ceremony vkey
    old = SnarkBackend()
    if old.available:
        nonce2 = verifier.issue_challenge()
        old_proof = await SessionProver(old, Clock()).prove(generate_identity(), nonce2, WG)
        assert not (await verifier.verify(old_proof, nonce2, WG)).valid
