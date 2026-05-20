from agent.data.rate_limiter import TokenBucket


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_bucket_starts_full():
    bucket = TokenBucket(capacity=3, refill_per_second=1.0, clock=FakeClock())

    assert bucket.try_acquire() is True
    assert bucket.try_acquire() is True
    assert bucket.try_acquire() is True


def test_bucket_blocks_when_empty():
    bucket = TokenBucket(capacity=2, refill_per_second=1.0, clock=FakeClock())

    bucket.try_acquire()
    bucket.try_acquire()

    assert bucket.try_acquire() is False


def test_bucket_refills_over_time():
    clock = FakeClock()
    bucket = TokenBucket(capacity=2, refill_per_second=1.0, clock=clock)
    bucket.try_acquire()
    bucket.try_acquire()
    assert bucket.try_acquire() is False

    clock.now = 1.0  # one second elapses -> one token refilled

    assert bucket.try_acquire() is True
    assert bucket.try_acquire() is False


def test_bucket_never_exceeds_capacity():
    clock = FakeClock()
    bucket = TokenBucket(capacity=2, refill_per_second=1.0, clock=clock)
    clock.now = 100.0  # long idle

    assert bucket.try_acquire() is True
    assert bucket.try_acquire() is True
    assert bucket.try_acquire() is False
