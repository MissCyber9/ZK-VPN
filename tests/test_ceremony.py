"""Multi-party ceremony: 3 contributors + beacon, verification, real proof, attacks."""

import asyncio
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from zkvpn.zk import SessionProver, SessionVerifier, SnarkBackend, generate_identity

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ceremony.sh"
WG = "A" * 43 + "="
pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(not (ROOT / "zk" / "node_modules" / "snarkjs").is_dir()
                       or not shutil.which("node"), reason="run scripts/setup_circuits.sh first"),
]


def run(*args, env, check=True):
    return subprocess.run([str(SCRIPT), *args], env=env, capture_output=True, text=True,
                          check=check, timeout=600)


@pytest.fixture(scope="module")
def ceremony(tmp_path_factory):
    d = tmp_path_factory.mktemp("ceremony")
    env = {**os.environ, "CEREMONY_DIR": str(d / "c"), "ZK_BUILD_DIR": str(d / "build")}
    run("init", "--dev", env=env)
    paths = [d / "c" / f"zkey_{i:04d}.zkey" for i in range(4)]
    for i, who in enumerate(("Alice", "Bob", "Carol"), start=1):
        run("contribute", str(paths[i - 1]), str(paths[i]), who, env=env)
    final = d / "c" / "zkey_final.zkey"
    run("beacon", str(paths[3]), str(final), "0123456789abcdef0123456789abcdef", env=env)
    return {"dir": d, "env": env, "paths": paths, "final": final}


def test_full_chain_verifies_and_lists_all_contributors(ceremony):
    r = run("verify", str(ceremony["final"]), env=ceremony["env"])
    assert "OK" in r.stdout
    for who in ("Alice", "Bob", "Carol"):
        assert who in r.stdout + r.stderr                   # every contribution is in the chain


def test_tampered_zkey_is_rejected(ceremony):
    bad = ceremony["dir"] / "c" / "tampered.zkey"
    data = bytearray(ceremony["final"].read_bytes())
    data[len(data) // 2] ^= 0xFF
    bad.write_bytes(bytes(data))
    assert run("verify", str(bad), env=ceremony["env"], check=False).returncode != 0


def test_zkey_from_another_ceremony_is_rejected(ceremony, tmp_path):
    env = {**ceremony["env"], "CEREMONY_DIR": str(tmp_path / "other"),
           "ZK_BUILD_DIR": str(tmp_path / "ob")}
    run("init", "--dev", env=env)                           # different phase 1 + entropy
    # verify the OTHER ceremony's key against THIS ceremony's ptau/manifest
    shutil.copy(tmp_path / "other" / "zkey_0000.zkey", tmp_path / "other" / "x.zkey")
    r = run("verify", str(tmp_path / "other" / "x.zkey"),
            env={**ceremony["env"]}, check=False)
    assert r.returncode != 0


def test_skipping_the_chain_start_is_rejected(ceremony):
    """A key whose chain does not start from the agreed zkey_0000 (different init) fails."""
    r = run("verify", str(ceremony["paths"][0]), env=ceremony["env"], check=False)
    assert r.returncode == 0                                # the untouched start is itself valid...
    # ...but a key produced from a *different* setup of the same circuit is not:
    forged = ceremony["dir"] / "c" / "forged.zkey"
    shutil.copy(ROOT / "zk" / "build" / "session_auth.zkey", forged)   # single-party dev key
    assert run("verify", str(forged), env=ceremony["env"], check=False).returncode != 0


def test_bad_beacon_input_rejected(ceremony):
    r = run("beacon", str(ceremony["paths"][3]), str(ceremony["dir"] / "x.zkey"), "zz",
            env=ceremony["env"], check=False)
    assert r.returncode != 0


async def test_proofs_work_with_ceremony_keys_and_not_with_old_ones(ceremony, tmp_path):
    env = ceremony["env"]
    run("finalize", str(ceremony["final"]), env=env)
    build = Path(env["ZK_BUILD_DIR"])
    assert "ceremony=multi-party" in (build / "CEREMONY.txt").read_text()

    zk = tmp_path / "zk"                                    # a zk dir that uses the ceremony build
    zk.mkdir()
    for f in ("prove.js", "verify.js"):
        shutil.copy(ROOT / "zk" / f, zk / f)
    os.symlink(ROOT / "zk" / "node_modules", zk / "node_modules")
    os.symlink(build, zk / "build")
    backend = SnarkBackend(zk_dir=str(zk))
    assert backend.available

    class Clock:
        def __call__(self):
            import time
            return time.time()

    prover, verifier = SessionProver(backend, Clock()), SessionVerifier(backend, clock=Clock())
    nonce = verifier.issue_challenge()
    proof = await prover.prove(generate_identity(), nonce, WG)
    assert (await verifier.verify(proof, nonce, WG)).valid

    # A proof made with the old single-party keys must NOT verify under the ceremony vkey
    old = SnarkBackend()                                    # zk/build = single-party dev keys
    if old.available:
        nonce2 = verifier.issue_challenge()
        old_proof = await SessionProver(old, Clock()).prove(generate_identity(), nonce2, WG)
        assert not (await verifier.verify(old_proof, nonce2, WG)).valid
