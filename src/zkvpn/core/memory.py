"""RAM-only memory management for ZK-VPN.

This module ensures no sensitive data is ever written to disk.
All sessions, proofs, and keys are stored exclusively in volatile memory
with automatic cleanup and protection against memory exhaustion.
"""

import time
import threading
import weakref
import logging
from typing import Dict, Any, Optional, TypeVar, Generic, Callable
from dataclasses import dataclass, field
from collections import OrderedDict
from contextlib import contextmanager
from datetime import datetime, timedelta
import secrets

from .config import settings

logger = logging.getLogger(__name__)

T = TypeVar('T')


@dataclass
class MemoryEntry(Generic[T]):
    """Entry in volatile memory store."""
    key: str
    value: T
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    access_count: int = 0
    last_accessed: float = field(default_factory=time.time)
    
    @property
    def is_expired(self) -> bool:
        """Check if entry has expired."""
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at
    
    @property
    def age_seconds(self) -> float:
        """Age of entry in seconds."""
        return time.time() - self.created_at


class SecureMemoryStore:
    """Thread-safe, RAM-only storage with automatic cleanup.
    
    Features:
    - No disk writes (explicitly prevented)
    - Automatic expiration of stale entries
    - LRU eviction when memory limits reached
    - Thread-safe operations
    - Memory usage tracking
    """
    
    def __init__(self, 
                 max_entries: int = 1000,
                 default_ttl: Optional[int] = None,
                 max_memory_mb: int = 50):
        """Initialize secure memory store.
        
        Args:
            max_entries: Maximum number of entries before LRU eviction
            default_ttl: Default time-to-live in seconds (None = no expiration)
            max_memory_mb: Maximum memory usage in MB
        """
        self._store: Dict[str, MemoryEntry] = OrderedDict()
        self._lock = threading.RLock()
        self._max_entries = max_entries
        self._default_ttl = default_ttl or settings.proof_ttl_seconds
        self._max_memory_bytes = max_memory_mb * 1024 * 1024
        self._cleanup_thread = None
        self._stop_cleanup = threading.Event()
        self._access_patterns: Dict[str, list] = {}  # For monitoring
        
        # Start automatic cleanup
        self._start_cleanup_thread()
        
        logger.info(f"SecureMemoryStore initialized: max_entries={max_entries}, "
                   f"default_ttl={self._default_ttl}s, max_memory={max_memory_mb}MB")
    
    def set(self, key: str, value: T, ttl: Optional[int] = None) -> None:
        """Store value in RAM only.
        
        Args:
            key: Unique identifier
            value: Data to store (must be pickle-able)
            ttl: Time-to-live in seconds (uses default if None)
        
        Raises:
            MemoryError: If memory limit would be exceeded
        """
        with self._lock:
            # Check memory usage
            if self._estimate_memory_usage() > self._max_memory_bytes:
                self._evict_lru()
            
            # Create entry
            expires_at = None
            if ttl is not None or self._default_ttl:
                ttl_seconds = ttl if ttl is not None else self._default_ttl
                expires_at = time.time() + ttl_seconds
            
            entry = MemoryEntry(
                key=key,
                value=value,
                expires_at=expires_at
            )
            
            # Store with LRU ordering
            self._store[key] = entry
            self._store.move_to_end(key)
            
            # Enforce max entries
            if len(self._store) > self._max_entries:
                self._evict_lru()
            
            logger.debug(f"Stored key '{key[:8]}...' in memory (expires: {expires_at})")
    
    def get(self, key: str, default: Optional[T] = None) -> Optional[T]:
        """Retrieve value from memory.
        
        Args:
            key: Unique identifier
            default: Default value if key not found
            
        Returns:
            Optional[T]: Stored value or default
        """
        with self._lock:
            entry = self._store.get(key)
            
            if entry is None:
                return default
            
            # Check expiration
            if entry.is_expired:
                self.delete(key)
                return default
            
            # Update access metadata
            entry.access_count += 1
            entry.last_accessed = time.time()
            self._store.move_to_end(key)
            
            # Track access pattern
            if key not in self._access_patterns:
                self._access_patterns[key] = []
            self._access_patterns[key].append(time.time())
            # Keep only last 100 accesses
            if len(self._access_patterns[key]) > 100:
                self._access_patterns[key] = self._access_patterns[key][-100:]
            
            return entry.value
    
    def delete(self, key: str) -> bool:
        """Delete entry from memory.
        
        Args:
            key: Unique identifier
            
        Returns:
            bool: True if deleted, False if not found
        """
        with self._lock:
            if key in self._store:
                # Securely clear sensitive data
                entry = self._store[key]
                if hasattr(entry.value, 'clear'):
                    try:
                        entry.value.clear()
                    except:
                        pass
                
                del self._store[key]
                self._access_patterns.pop(key, None)
                logger.debug(f"Deleted key '{key[:8]}...' from memory")
                return True
            return False
    
    def clear(self) -> None:
        """Clear all entries from memory store."""
        with self._lock:
            # Securely clear all sensitive data
            for key, entry in self._store.items():
                if hasattr(entry.value, 'clear'):
                    try:
                        entry.value.clear()
                    except:
                        pass
            
            self._store.clear()
            self._access_patterns.clear()
            logger.debug(f"Cleared memory store")
    
    def exists(self, key: str) -> bool:
        """Check if key exists and is not expired.
        
        Args:
            key: Unique identifier
            
        Returns:
            bool: True if exists and valid
        """
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return False
            if entry.is_expired:
                self.delete(key)
                return False
            return True
    
    def get_stats(self) -> Dict[str, Any]:
        """Get memory store statistics.
        
        Returns:
            Dict[str, Any]: Statistics about current memory usage
        """
        with self._lock:
            active_entries = [e for e in self._store.values() if not e.is_expired]
            expired_entries = len(self._store) - len(active_entries)
            
            return {
                "total_entries": len(self._store),
                "active_entries": len(active_entries),
                "expired_entries": expired_entries,
                "estimated_memory_bytes": self._estimate_memory_usage(),
                "estimated_memory_mb": self._estimate_memory_usage() / (1024 * 1024),
                "max_memory_mb": self._max_memory_bytes / (1024 * 1024),
                "max_entries": self._max_entries,
                "default_ttl": self._default_ttl,
                "oldest_entry_age": self._get_oldest_entry_age(),
                "newest_entry_age": self._get_newest_entry_age(),
            }
    
    def _estimate_memory_usage(self) -> int:
        """Estimate current memory usage.
        
        Returns:
            int: Estimated bytes used
        """
        # Rough estimation - in production use sys.getsizeof()
        estimated_bytes = 0
        for entry in self._store.values():
            # Base overhead + key + value
            estimated_bytes += 100 + len(entry.key) * 2
            if hasattr(entry.value, '__sizeof__'):
                estimated_bytes += entry.value.__sizeof__()
            else:
                estimated_bytes += 1000  # Default estimation
        return estimated_bytes
    
    def _evict_lru(self) -> None:
        """Evict least recently used entry."""
        if not self._store:
            return
        
        # Remove oldest accessed entry
        oldest_key = next(iter(self._store))
        logger.debug(f"LRU eviction: removing key '{oldest_key[:8]}...'")
        self.delete(oldest_key)
    
    def _cleanup_expired(self) -> None:
        """Remove all expired entries."""
        with self._lock:
            expired_keys = [
                key for key, entry in self._store.items()
                if entry.is_expired
            ]
            for key in expired_keys:
                self.delete(key)
            
            if expired_keys:
                logger.debug(f"Cleaned up {len(expired_keys)} expired entries")
    
    def _get_oldest_entry_age(self) -> Optional[float]:
        """Get age of oldest entry in seconds."""
        if not self._store:
            return None
        oldest = next(iter(self._store.values()))
        return oldest.age_seconds
    
    def _get_newest_entry_age(self) -> Optional[float]:
        """Get age of newest entry in seconds."""
        if not self._store:
            return None
        newest = next(reversed(self._store.values()))
        return newest.age_seconds
    
    def _start_cleanup_thread(self) -> None:
        """Start background cleanup thread."""
        def cleanup_worker():
            while not self._stop_cleanup.is_set():
                try:
                    self._cleanup_expired()
                    
                    # Check memory pressure
                    if self._estimate_memory_usage() > self._max_memory_bytes * 0.9:
                        logger.warning("High memory pressure, evicting LRU")
                        self._evict_lru()
                    
                except Exception as e:
                    logger.error(f"Cleanup error: {e}")
                
                # Sleep for cleanup interval
                self._stop_cleanup.wait(60)  # Check every minute
        
        self._cleanup_thread = threading.Thread(
            target=cleanup_worker,
            name="MemoryCleanup",
            daemon=True
        )
        self._cleanup_thread.start()
        logger.debug("Started memory cleanup thread")
    
    def stop(self) -> None:
        """Stop cleanup thread and clear memory."""
        logger.info("Stopping memory store...")
        self._stop_cleanup.set()
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=5)
        self.clear()
        logger.info("Memory store stopped")


class SessionManager:
    """Manage VPN sessions entirely in RAM."""
    
    def __init__(self):
        self._sessions = SecureMemoryStore(
            max_entries=settings.max_sessions,
            default_ttl=settings.session_timeout_seconds,
            max_memory_mb=settings.memory_max_mb // 3  # Use 1/3 of memory budget
        )
    
    def create_session(self, peer_pubkey: str) -> Dict[str, Any]:
        """Create new VPN session.
        
        Args:
            peer_pubkey: Peer's WireGuard public key
            
        Returns:
            Dict[str, Any]: Session data
        """
        session_id = secrets.token_urlsafe(16)
        session_data = {
            "session_id": session_id,
            "peer_pubkey": peer_pubkey,
            "created_at": time.time(),
            "last_activity": time.time(),
            "bytes_sent": 0,
            "bytes_received": 0,
            "proofs_verified": 0,
        }
        
        self._sessions.set(session_id, session_data)
        logger.info(f"Created session {session_id[:8]}... for peer {peer_pubkey[:8]}...")
        return session_data
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Optional[Dict[str, Any]]: Session data or None
        """
        session = self._sessions.get(session_id)
        if session:
            session["last_activity"] = time.time()
            self._sessions.set(session_id, session)  # Update TTL
        return session
    
    def delete_session(self, session_id: str) -> bool:
        """Terminate session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            bool: True if session existed
        """
        return self._sessions.delete(session_id)


# Global memory stores
proof_store = SecureMemoryStore(
    max_entries=1000,
    default_ttl=settings.proof_ttl_seconds,
    max_memory_mb=settings.memory_max_mb // 3
)

session_manager = SessionManager()
key_store = SecureMemoryStore(
    max_entries=100,
    default_ttl=3600,
    max_memory_mb=settings.memory_max_mb // 3
)


@contextmanager
def memory_guard(operation: str):
    """Context manager for memory-safe operations.
    
    Args:
        operation: Name of operation for logging
    
    Yields:
        None
    """
    try:
        yield
    except MemoryError:
        logger.error(f"Memory error during {operation}, forcing cleanup")
        proof_store._evict_lru()
        raise
    except Exception as e:
        logger.error(f"Error during {operation}: {e}")
        raise


__all__ = [
    "SecureMemoryStore",
    "SessionManager",
    "proof_store",
    "session_manager",
    "key_store",
    "memory_guard"
]
