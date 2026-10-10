"""Tests for the (simulated) ZK circuit and prover."""

from zkvpn.circuits.no_logging import NoLoggingCircuit
from zkvpn.circuits.prover import ZKProver


def test_no_logging_circuit():
    circuit = NoLoggingCircuit()
    proof = circuit.generate_proof({"test": "data", "user": "test_user"})

    assert proof["circuit"] == "no_logging_v1"
    assert "public_inputs" in proof
    assert "proof" in proof
    assert circuit.verify_proof(proof) is True
    assert circuit.verify_proof({"circuit": "wrong"}) is False


async def test_prover_generates_proofs():
    prover = ZKProver(deterministic=True)
    proof = await prover.generate_proof()
    assert proof.circuit_name == "no_logging"
    assert prover.get_stats()["proofs_generated"] == 1

    await prover.generate_proof(prev_proof=proof)
    assert prover.get_stats()["proofs_generated"] == 2
