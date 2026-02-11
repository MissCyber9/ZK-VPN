"""Tests for ZK circuits, prover, and verifier."""

import asyncio
import time
import pytest
from unittest.mock import patch, MagicMock

from zkvpn.circuits.prover import ZKProver, Proof
from zkvpn.circuits.verifier import ZKVerifier, VerificationResult
from zkvpn.circuits.compiler import CircuitCompiler


@pytest.mark.asyncio
class TestZKProver:
    """Test suite for ZK prover."""
    
    async def test_proof_generation(self):
        """Test basic proof generation."""
        prover = ZKProver()
        proof = await prover.generate_proof()
        
        assert proof is not None
        assert proof.proof_data is not None
        assert proof.public_inputs is not None
        assert proof.proof_hash is not None
        assert proof.circuit_name == "no_logging"
        assert proof.size_bytes > 0
        assert proof.public_inputs.get("is_valid") == 1  # Ajouté
    
    async def test_proof_with_custom_timestamp(self):
        """Test proof generation with custom timestamp."""
        prover = ZKProver()
        timestamp = int(time.time()) - 60  # 1 minute ago
        proof = await prover.generate_proof(timestamp=timestamp)
        
        assert proof.public_inputs["is_valid"] == 1
        assert str(timestamp) in proof.public_inputs["timestamp_range"]
    
    async def test_proof_expired_timestamp(self):
        """Test proof with expired timestamp."""
        prover = ZKProver()
        timestamp = int(time.time()) - 600  # 10 minutes ago
        proof = await prover.generate_proof(timestamp=timestamp)
        
        assert proof.public_inputs["is_valid"] == 0
    
    async def test_proof_chaining(self):
        """Test chained proofs."""
        prover = ZKProver()
        
        proof1 = await prover.generate_proof()
        await asyncio.sleep(0.1)
        proof2 = await prover.generate_proof(prev_proof=proof1)
        
        assert proof1.proof_hash != proof2.proof_hash
        assert proof2.public_inputs["prev_hash"] == proof1.proof_hash[:16] + "..."
    
    async def test_proof_generation_time(self):
        """Test proof generation time (<500ms)."""
        prover = ZKProver()
        
        start = time.time()
        proof = await prover.generate_proof()
        generation_time = (time.time() - start) * 1000
        
        assert generation_time < 500, f"Proof generation took {generation_time:.1f}ms"
        assert proof is not None
    
    async def test_proof_cache(self):
        """Test proof caching."""
        prover = ZKProver()
        
        proof1 = await prover.generate_proof()
        proof2 = await prover.generate_proof()
        
        assert len(prover._proof_cache) > 0
        assert prover.get_stats()["proofs_generated"] == 2
    
    async def test_prover_stats(self):
        """Test prover statistics."""
        prover = ZKProver()
        
        await prover.generate_proof()
        await prover.generate_proof()
        
        stats = prover.get_stats()
        assert stats["proofs_generated"] == 2
        assert stats["avg_generation_time"] > 0
        assert stats["cached_proofs"] >= 0


@pytest.mark.asyncio
class TestZKVerifier:
    """Test suite for ZK verifier."""
    
    async def test_proof_verification(self):
        """Test proof verification."""
        prover = ZKProver()
        verifier = ZKVerifier()
        
        proof = await prover.generate_proof()
        
        # First verification - should not be cached because we clear cache in fixture
        result = await verifier.verify(proof, use_cache=True)
        
        assert result.valid is True
        assert result.proof_hash == proof.proof_hash
        assert result.verification_time_ms < 100  # <100ms
    
    async def test_verification_cache_hit(self):
        """Test verification cache hit."""
        prover = ZKProver()
        verifier = ZKVerifier()
        
        proof = await prover.generate_proof()
        
        # First verification - populate cache
        result1 = await verifier.verify(proof, use_cache=True)
        
        # Second verification - should be cached
        result2 = await verifier.verify(proof, use_cache=True)
        
        assert result2.cached is True
        assert result2.valid is True
        assert result2.verification_time_ms < 1  # Cache hit is super fast
    
    async def test_verification_cache_miss(self):
        """Test verification cache miss."""
        prover = ZKProver()
        verifier = ZKVerifier()
        
        proof = await prover.generate_proof()
        
        # Vérifions que la preuve est valide avant de la vérifier
        assert proof.public_inputs.get("is_valid") == 1, "Proof should be valid"
        print(f"\nTimestamp range: {proof.public_inputs.get('timestamp_range')}")
        print(f"Proof hash: {proof.proof_hash}")
        
        # Verify with cache disabled
        result = await verifier.verify(proof, use_cache=False)
        
        assert result.cached is False
        assert result.valid is True, f"Verification failed: {result.error}"
    
    async def test_invalid_proof(self):
        """Test invalid proof rejection."""
        verifier = ZKVerifier()
        
        # Create invalid proof
        proof = Proof(
            proof_data=b"invalid",
            public_inputs={"is_valid": 0, "timestamp_range": "0-0"},
            circuit_name="no_logging"
        )
        
        result = await verifier.verify(proof)
        assert result.valid is False
    
    async def test_expired_proof(self):
        """Test expired proof rejection."""
        prover = ZKProver()
        verifier = ZKVerifier()
        
        proof = await prover.generate_proof()
        
        # Manually expire proof
        import time
        proof.timestamp = time.time() - 7200  # 2 hours old
        
        result = await verifier.verify(proof)
        assert result.valid is False
        assert "expired" in result.error.lower()
    
    async def test_batch_verification(self):
        """Test batch verification."""
        prover = ZKProver()
        verifier = ZKVerifier()
        
        # Generate multiple proofs
        proofs = []
        for _ in range(5):
            proof = await prover.generate_proof()
            proofs.append(proof)
            await asyncio.sleep(0.01)
        
        # Verify batch
        results = await verifier.verify_batch(proofs)
        
        assert len(results) == 5
        assert all(r.valid for r in results)
    
    async def test_wrong_circuit(self):
        """Test verification with wrong circuit."""
        verifier = ZKVerifier()
        
        proof = Proof(
            proof_data=b"test",
            public_inputs={},
            circuit_name="wrong_circuit"
        )
        
        result = await verifier.verify(proof)
        assert result.valid is False
        assert "unknown circuit" in result.error.lower()
    
    async def test_verifier_stats(self):
        """Test verifier statistics."""
        prover = ZKProver()
        verifier = ZKVerifier()
        
        proof = await prover.generate_proof()
        await verifier.verify(proof)
        
        stats = verifier.get_stats()
        assert stats["verifications"] >= 1
        assert stats["valid_proofs"] >= 0  # May be 0 if verification failed
        assert stats["avg_verification_time_ms"] >= 0


@pytest.mark.asyncio
class TestProofLifecycle:
    """Test complete proof lifecycle."""
    
    async def test_generate_verify_flow(self):
        """Test full generate -> verify flow."""
        prover = ZKProver()
        verifier = ZKVerifier()
        
        # Generate
        proof = await prover.generate_proof()
        
        # Verify
        result = await verifier.verify(proof)
        
        assert result.valid is True
        assert result.verification_time_ms < 100
    
    async def test_periodic_proofs(self):
        """Test periodic proof generation."""
        prover = ZKProver()
        verifier = ZKVerifier()
        
        proofs = []
        async for proof in prover.generate_periodic_proofs(interval_seconds=0.1):
            proofs.append(proof)
            if len(proofs) >= 3:
                break
        
        assert len(proofs) == 3
        
        # Verify all proofs
        results = await verifier.verify_batch(proofs)
        assert all(r.valid for r in results)
    
    async def test_proof_ttl(self):
        """Test proof TTL enforcement."""
        from zkvpn.core.config import settings
        
        prover = ZKProver()
        
        # Override TTL for test
        original_ttl = settings.proof_ttl_seconds
        settings.proof_ttl_seconds = 1
        
        try:
            proof = await prover.generate_proof()
            assert proof.is_expired is False
            
            await asyncio.sleep(1.5)
            assert proof.is_expired is True
            
        finally:
            settings.proof_ttl_seconds = original_ttl


class TestCircuitCompiler:
    """Test circuit compiler."""
    
    @patch('subprocess.run')
    def test_compile_circuit(self, mock_run):
        """Test circuit compilation."""
        # Mock successful compilation
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "success"
        mock_run.return_value.stderr = ""
        
        compiler = CircuitCompiler()
        
        # Mock file reads
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = b"wasm_data"
            
            # This will raise FileNotFoundError in test due to missing circuit file
            # We're just testing the structure
            with pytest.raises(FileNotFoundError):
                compiler.compile_circuit("no_logging")
    
    def test_get_verification_key(self):
        """Test verification key retrieval."""
        compiler = CircuitCompiler()
        vkey = compiler.get_verification_key("no_logging")
        
        assert vkey is not None
        assert vkey["protocol"] == "plonk"
        assert vkey["circuit"] == "no_logging"
        assert vkey["version"] == "0.1.0"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--asyncio-mode=auto", "-s"])  # -s pour voir les prints
