import asyncio
import time
from collections.abc import Callable


class TokenBucket:
    """A token-bucket rate limiter.

    `try_acquire` is synchronous and deterministic (inject `clock` for tests).
    `acquire` is an async wrapper that waits until a token is available.
    """

    def __init__(
        self,
        capacity: int,
        refill_per_second: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self._clock = clock
        self._tokens = float(capacity)
        self._last = clock()

    def _refill(self) -> None:
        now = self._clock()
        elapsed = now - self._last
        self._tokens = min(
            self.capacity, self._tokens + elapsed * self.refill_per_second
        )
        self._last = now

    def try_acquire(self, tokens: int = 1) -> bool:
        """Consume `tokens` if available. Return True on success."""
        self._refill()
        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False

    async def acquire(self, tokens: int = 1) -> None:
        """Wait until `tokens` can be consumed, then consume them."""
        while not self.try_acquire(tokens):
            await asyncio.sleep(1.0 / self.refill_per_second)
