"""
Account Lockout Protection
Prevents brute-force password attacks via account lockout

SECURITY (SEC-012 Fix): Account lockout after failed login attempts
"""

import time
import logging
from typing import Optional, Tuple
from redis import Redis

logger = logging.getLogger(__name__)


class AccountLockoutManager:
    """
    Manages account lockout after failed login attempts

    Protects against:
    - Brute force password attacks
    - Credential stuffing attacks
    - Dictionary attacks

    Uses Redis for distributed tracking across multiple workers/servers
    """

    def __init__(
        self,
        redis_client: Optional[Redis] = None,
        max_attempts: int = 5,
        lockout_duration: int = 900,  # 15 minutes
        attempt_window: int = 300,  # 5 minutes
    ):
        """
        Initialize account lockout manager

        Args:
            redis_client: Redis client for distributed tracking
            max_attempts: Maximum failed attempts before lockout (default: 5)
            lockout_duration: Lockout duration in seconds (default: 900 = 15 min)
            attempt_window: Time window for counting attempts (default: 300 = 5 min)
        """
        self.redis_client = redis_client
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration
        self.attempt_window = attempt_window

        # Fallback to in-memory if Redis not available (not production-ready)
        self._memory_store = {} if not redis_client else None

        if not redis_client:
            logger.warning(
                "Account lockout using in-memory storage. "
                "Configure Redis for production-grade account protection."
            )

    def record_failed_attempt(self, identifier: str) -> None:
        """
        Record a failed login attempt

        Args:
            identifier: User identifier (email, user_id, or IP address)
        """
        if self.redis_client:
            self._record_failed_attempt_redis(identifier)
        else:
            self._record_failed_attempt_memory(identifier)

    def record_successful_login(self, identifier: str) -> None:
        """
        Record a successful login (clears failed attempts)

        Args:
            identifier: User identifier (email, user_id, or IP address)
        """
        if self.redis_client:
            self._clear_attempts_redis(identifier)
        else:
            self._clear_attempts_memory(identifier)

    def is_locked_out(self, identifier: str) -> Tuple[bool, Optional[int]]:
        """
        Check if account is currently locked out

        Args:
            identifier: User identifier (email, user_id, or IP address)

        Returns:
            Tuple of (is_locked, seconds_remaining)
        """
        if self.redis_client:
            return self._is_locked_out_redis(identifier)
        else:
            return self._is_locked_out_memory(identifier)

    def get_remaining_attempts(self, identifier: str) -> int:
        """
        Get number of remaining login attempts before lockout

        Args:
            identifier: User identifier (email, user_id, or IP address)

        Returns:
            Number of remaining attempts (0 if locked out)
        """
        if self.redis_client:
            return self._get_remaining_attempts_redis(identifier)
        else:
            return self._get_remaining_attempts_memory(identifier)

    # ============================================================================
    # REDIS IMPLEMENTATION (Production-ready)
    # ============================================================================

    def _record_failed_attempt_redis(self, identifier: str) -> None:
        """Record failed attempt using Redis"""
        attempts_key = f"login_attempts:{identifier}"
        lockout_key = f"account_lockout:{identifier}"

        current_time = time.time()

        try:
            # Use pipeline for atomic operations
            pipe = self.redis_client.pipeline()

            # Add current attempt to sorted set
            pipe.zadd(attempts_key, {str(current_time): current_time})

            # Remove old attempts outside the window
            pipe.zremrangebyscore(attempts_key, 0, current_time - self.attempt_window)

            # Get count of recent attempts
            pipe.zcard(attempts_key)

            # Set expiration to prevent memory leak
            pipe.expire(attempts_key, self.attempt_window)

            # Execute pipeline
            results = pipe.execute()
            attempt_count = results[2]  # Result from zcard

            # Check if lockout threshold reached
            if attempt_count >= self.max_attempts:
                # Lock account
                self.redis_client.setex(
                    lockout_key,
                    self.lockout_duration,
                    str(current_time)
                )

                logger.warning(
                    f"Account locked out: {identifier}",
                    extra={
                        "identifier": identifier,
                        "attempts": attempt_count,
                        "lockout_duration": self.lockout_duration,
                    }
                )

        except Exception as e:
            logger.error(f"Failed to record login attempt: {e}", exc_info=True)

    def _is_locked_out_redis(self, identifier: str) -> Tuple[bool, Optional[int]]:
        """Check if account is locked out using Redis"""
        lockout_key = f"account_lockout:{identifier}"

        try:
            # Check if lockout key exists
            lockout_time = self.redis_client.get(lockout_key)

            if lockout_time:
                # Get remaining TTL
                ttl = self.redis_client.ttl(lockout_key)
                return True, max(0, ttl)

            return False, None

        except Exception as e:
            logger.error(f"Failed to check lockout status: {e}", exc_info=True)
            return False, None  # Fail open (allow login on error)

    def _get_remaining_attempts_redis(self, identifier: str) -> int:
        """Get remaining attempts using Redis"""
        attempts_key = f"login_attempts:{identifier}"
        current_time = time.time()

        try:
            # Remove old attempts
            self.redis_client.zremrangebyscore(
                attempts_key,
                0,
                current_time - self.attempt_window
            )

            # Count recent attempts
            attempt_count = self.redis_client.zcard(attempts_key)

            remaining = max(0, self.max_attempts - attempt_count)
            return remaining

        except Exception as e:
            logger.error(f"Failed to get remaining attempts: {e}", exc_info=True)
            return self.max_attempts  # Fail open

    def _clear_attempts_redis(self, identifier: str) -> None:
        """Clear failed attempts using Redis"""
        attempts_key = f"login_attempts:{identifier}"
        lockout_key = f"account_lockout:{identifier}"

        try:
            pipe = self.redis_client.pipeline()
            pipe.delete(attempts_key)
            pipe.delete(lockout_key)
            pipe.execute()

            logger.debug(f"Cleared login attempts for: {identifier}")

        except Exception as e:
            logger.error(f"Failed to clear attempts: {e}", exc_info=True)

    # ============================================================================
    # IN-MEMORY IMPLEMENTATION (Development/Testing only)
    # ============================================================================

    def _record_failed_attempt_memory(self, identifier: str) -> None:
        """Record failed attempt using in-memory storage"""
        current_time = time.time()

        if identifier not in self._memory_store:
            self._memory_store[identifier] = {
                "attempts": [],
                "locked_until": None
            }

        # Add attempt
        self._memory_store[identifier]["attempts"].append(current_time)

        # Remove old attempts
        self._memory_store[identifier]["attempts"] = [
            t for t in self._memory_store[identifier]["attempts"]
            if t > current_time - self.attempt_window
        ]

        # Check if should lock
        if len(self._memory_store[identifier]["attempts"]) >= self.max_attempts:
            self._memory_store[identifier]["locked_until"] = current_time + self.lockout_duration

            logger.warning(
                f"Account locked out (memory): {identifier}",
                extra={
                    "identifier": identifier,
                    "attempts": len(self._memory_store[identifier]["attempts"]),
                    "lockout_duration": self.lockout_duration,
                }
            )

    def _is_locked_out_memory(self, identifier: str) -> Tuple[bool, Optional[int]]:
        """Check if account is locked out using memory"""
        if identifier not in self._memory_store:
            return False, None

        locked_until = self._memory_store[identifier].get("locked_until")

        if locked_until:
            current_time = time.time()
            if current_time < locked_until:
                remaining = int(locked_until - current_time)
                return True, remaining
            else:
                # Lockout expired
                self._memory_store[identifier]["locked_until"] = None
                return False, None

        return False, None

    def _get_remaining_attempts_memory(self, identifier: str) -> int:
        """Get remaining attempts using memory"""
        if identifier not in self._memory_store:
            return self.max_attempts

        current_time = time.time()

        # Remove old attempts
        self._memory_store[identifier]["attempts"] = [
            t for t in self._memory_store[identifier]["attempts"]
            if t > current_time - self.attempt_window
        ]

        attempt_count = len(self._memory_store[identifier]["attempts"])
        remaining = max(0, self.max_attempts - attempt_count)

        return remaining

    def _clear_attempts_memory(self, identifier: str) -> None:
        """Clear failed attempts using memory"""
        if identifier in self._memory_store:
            self._memory_store[identifier] = {
                "attempts": [],
                "locked_until": None
            }
            logger.debug(f"Cleared login attempts (memory) for: {identifier}")
