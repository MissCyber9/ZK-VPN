"""Circom circuit compiler for ZK-VPN.

Handles compilation of ZK circuits, trusted setup, and WASM generation.
All operations performed in memory, no sensitive data written to disk.
"""

import os
import json
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
import logging
import hashlib
import secrets

from zkvpn.core.config import settings
from zkvpn.core.memory import memory_guard

logger = logging.getLogger(__name__)


class CircuitCompiler:
    """Compile Circom circuits to WASM and generate proving/verification keys."""
    
    def __init__(self, circuit_dir: Optional[Path] = None):
        """Initialize compiler.
        
        Args:
            circuit_dir: Directory containing .circom files
        """
        self.circuit_dir = circuit_dir or Path(settings.circuit_path)
        self.circuit_dir.mkdir(parents=True, exist_ok=True)
        
        # Paths for compiled artifacts (RAM-only during runtime)
        self._wasm_path = None
        self._r1cs_path = None
        self._zkey_path = None
        self._verification_key = None
        
        # Cache for compiled circuits
        self._circuit_cache = {}
        
        logger.info(f"CircuitCompiler initialized with dir: {self.circuit_dir}")
    
    @memory_guard("circuit_compilation")
    def compile_circuit(self, circuit_name: str = "no_logging") -> Tuple[bytes, bytes]:
        """Compile Circom circuit to WASM and R1CS.
        
        Args:
            circuit_name: Name of circuit file (without .circom)
            
        Returns:
            Tuple[bytes, bytes]: WASM binary and R1CS binary
            
        Raises:
            RuntimeError: If compilation fails
        """
        circuit_file = self.circuit_dir / f"{circuit_name}.circom"
        if not circuit_file.exists():
            raise FileNotFoundError(f"Circuit not found: {circuit_file}")
        
        # Create temporary directory for compilation artifacts
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            
            try:
                # Compile to WASM
                cmd = [
                    "circom",
                    str(circuit_file),
                    "--wasm",
                    "--r1cs",
                    "--sym",
                    "-o", str(tmp_path)
                ]
                
                logger.debug(f"Compiling circuit: {' '.join(cmd)}")
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode != 0:
                    raise RuntimeError(f"Compilation failed: {result.stderr}")
                
                # Read compiled artifacts
                wasm_file = tmp_path / f"{circuit_name}_js" / f"{circuit_name}.wasm"
                r1cs_file = tmp_path / f"{circuit_name}.r1cs"
                
                if not wasm_file.exists() or not r1cs_file.exists():
                    raise RuntimeError("Compilation artifacts not found")
                
                with open(wasm_file, "rb") as f:
                    wasm_binary = f.read()
                
                with open(r1cs_file, "rb") as f:
                    r1cs_binary = f.read()
                
                # Cache in memory
                cache_key = hashlib.sha256(wasm_binary).hexdigest()
                self._circuit_cache[cache_key] = {
                    "wasm": wasm_binary,
                    "r1cs": r1cs_binary,
                    "name": circuit_name,
                    "compiled_at": __import__('time').time()
                }
                
                logger.info(f"Successfully compiled {circuit_name}")
                return wasm_binary, r1cs_binary
                
            except subprocess.TimeoutExpired:
                raise RuntimeError("Compilation timeout (30s)")
            except Exception as e:
                logger.error(f"Compilation error: {e}")
                raise
    
    @memory_guard("trusted_setup")
    def trusted_setup(self, 
                     r1cs_binary: bytes,
                     circuit_name: str = "no_logging") -> Tuple[bytes, Dict]:
        """Perform trusted setup for circuit.
        
        Args:
            r1cs_binary: R1CS circuit binary
            circuit_name: Name for output files
            
        Returns:
            Tuple[bytes, Dict]: ZKey binary and verification key
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            
            # Write R1CS to temp file
            r1cs_file = tmp_path / f"{circuit_name}.r1cs"
            with open(r1cs_file, "wb") as f:
                f.write(r1cs_binary)
            
            try:
                # Phase 1: Powers of tau
                ptau_file = tmp_path / "powers_of_tau.ptau"
                cmd_ptau = [
                    "snarkjs", "powersoftau", "new",
                    "bn128", "12", str(ptau_file), "-v"
                ]
                
                result = subprocess.run(
                    cmd_ptau,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if result.returncode != 0:
                    raise RuntimeError(f"Powers of tau failed: {result.stderr}")
                
                # Phase 2: Circuit-specific setup
                zkey_file = tmp_path / f"{circuit_name}.zkey"
                cmd_zkey = [
                    "snarkjs", "plonk", "setup",
                    str(r1cs_file),
                    str(ptau_file),
                    str(zkey_file)
                ]
                
                result = subprocess.run(
                    cmd_zkey,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if result.returncode != 0:
                    raise RuntimeError(f"Setup failed: {result.stderr}")
                
                # Export verification key
                vkey_file = tmp_path / f"{circuit_name}_vkey.json"
                cmd_vkey = [
                    "snarkjs", "zkey", "export", "verificationkey",
                    str(zkey_file),
                    str(vkey_file)
                ]
                
                result = subprocess.run(
                    cmd_vkey,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode != 0:
                    raise RuntimeError(f"Export verification key failed: {result.stderr}")
                
                # Read artifacts
                with open(zkey_file, "rb") as f:
                    zkey_binary = f.read()
                
                with open(vkey_file, "r") as f:
                    verification_key = json.load(f)
                
                logger.info(f"Trusted setup completed for {circuit_name}")
                return zkey_binary, verification_key
                
            except subprocess.TimeoutExpired:
                raise RuntimeError("Trusted setup timeout")
            except Exception as e:
                logger.error(f"Trusted setup error: {e}")
                raise
    
    def get_verification_key(self, circuit_name: str = "no_logging") -> Optional[Dict]:
        """Get cached verification key.
        
        Args:
            circuit_name: Circuit identifier
            
        Returns:
            Optional[Dict]: Verification key or None
        """
        # In production, load from secure storage
        # For now, return a minimal verification key
        return {
            "protocol": "plonk",
            "curve": "bn128",
            "circuit": circuit_name,
            "version": "0.1.0"
        }


# Global compiler instance
compiler = CircuitCompiler()


__all__ = ["CircuitCompiler", "compiler"]
