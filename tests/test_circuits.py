"""
Tests des circuits ZK
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../src'))

def test_no_logging_circuit():
    """Test le circuit no-logging"""
    try:
        from zkvpn.circuits.no_logging import NoLoggingCircuit
        
        circuit = NoLoggingCircuit()
        
        # Test génération preuve
        test_data = {"test": "data", "user": "test_user"}
        proof = circuit.generate_proof(test_data)
        
        assert "circuit" in proof
        assert proof["circuit"] == "no_logging_v1"
        assert "public_inputs" in proof
        assert "proof" in proof
        
        # Test vérification
        assert circuit.verify_proof(proof) == True
        
        # Test avec données invalides
        invalid_proof = {"circuit": "wrong"}
        assert circuit.verify_proof(invalid_proof) == False
        
        return True
    except Exception as e:
        print(f"Erreur test circuit: {e}")
        return False

def test_prover():
    """Test le prover ZK"""
    try:
        from zkvpn.circuits.prover import ZKProver
        
        prover = ZKProver()
        
        # Générer une preuve
        proof = prover.prove_no_logging({"action": "test"})
        
        assert proof is not None
        assert prover.get_stats()["total_proofs"] == 1
        
        # Générer une autre preuve
        prover.prove_no_logging({"action": "test2"})
        assert prover.get_stats()["total_proofs"] == 2
        
        return True
    except Exception as e:
        print(f"Erreur test prover: {e}")
        return False

if __name__ == "__main__":
    print("🧪 Tests circuits ZK")
    print(f"No-logging circuit: {'✅' if test_no_logging_circuit() else '❌'}")
    print(f"Prover: {'✅' if test_prover() else '❌'}")
