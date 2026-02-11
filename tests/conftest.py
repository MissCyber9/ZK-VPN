"""Pytest configuration and fixtures for ZK-VPN tests."""

import pytest
import asyncio
from zkvpn.core.memory import proof_store, session_manager, key_store
from zkvpn.circuits.prover import prover
from zkvpn.circuits.verifier import verifier


@pytest.fixture(autouse=True)
async def clear_caches():
    """Clear all caches before each test."""
    # Clear memory stores
    proof_store.clear()
    session_manager._sessions.clear()
    key_store.clear()
    
    # Clear circuit caches
    await prover.clear_cache()
    await verifier.clear_cache()
    
    yield
    
    # Cleanup after test
    proof_store.clear()
    session_manager._sessions.clear()
    key_store.clear()
    await prover.clear_cache()
    await verifier.clear_cache()


@pytest.fixture
def event_loop():
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()
