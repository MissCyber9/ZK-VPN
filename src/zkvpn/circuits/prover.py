"""
ZK Prover pour ZK-VPN
"""

import time
from typing import Dict, Any, List
from .no_logging import NoLoggingCircuit, generate_proof

class ZKProver:
    """Générateur de preuves ZK pour ZK-VPN"""
    
    def __init__(self):
        self.circuit = NoLoggingCircuit()
        self.proof_history: List[Dict] = []
        self.start_time = time.time()
    
    def prove_no_logging(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """Génère une preuve de non-logging pour une session"""
        # Ajouter un timestamp si absent
        if "timestamp" not in session_data:
            session_data["timestamp"] = time.time()
        
        # Générer la preuve
        proof = generate_proof(session_data)
        
        # Enregistrer dans l'historique
        record = {
            "timestamp": time.time(),
            "session_data": {k: v for k, v in session_data.items() if k != "private"},
            "proof_hash": proof.get("witness_hash", ""),
            "circuit": proof["circuit"]
        }
        self.proof_history.append(record)
        
        return proof
    
    def prove_bandwidth(self, used: int, limit: int) -> Dict[str, Any]:
        """Preuve que la bande passante utilisée est sous la limite"""
        session_data = {
            "type": "bandwidth_check",
            "used_bytes": used,
            "limit_bytes": limit,
            "compliance": used < limit,
            "timestamp": time.time()
        }
        
        return self.prove_no_logging(session_data)
    
    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques du prover"""
        return {
            "total_proofs": len(self.proof_history),
            "uptime": time.time() - self.start_time,
            "circuit": self.circuit.circuit_id,
            "last_proof_time": self.proof_history[-1]["timestamp"] if self.proof_history else 0
        }
    
    def clear_history(self):
        """Efface l'historique (pour la confidentialité)"""
        self.proof_history.clear()

# Instance globale
default_prover = ZKProver()

if __name__ == "__main__":
    prover = ZKProver()
    
    # Test
    test_session = {"user_id": "user123", "action": "vpn_connect"}
    proof = prover.prove_no_logging(test_session)
    
    print(f"✅ Preuves générées: {prover.get_stats()['total_proofs']}")
    print(f"📊 Proof: {proof['circuit']} ({len(str(proof))} chars)")
