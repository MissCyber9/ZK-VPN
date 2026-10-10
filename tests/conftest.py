"""Pytest configuration and fixtures for ZK-VPN tests."""

import pytest
from zkvpn.core.memory import proof_store, session_manager, key_store


@pytest.fixture(autouse=True)
async def clear_caches():
    """Clear all caches before each test."""
    # Clear memory stores
    proof_store.clear()
    session_manager._sessions.clear()
    key_store.clear()
    
    yield
    
    # Cleanup after test
    proof_store.clear()
    session_manager._sessions.clear()
    key_store.clear()
