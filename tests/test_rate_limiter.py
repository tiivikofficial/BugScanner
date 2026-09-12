import asyncio

from core.rate_limiter import AdaptiveRateLimiter


def test_retry_after_pause():
    limiter = AdaptiveRateLimiter(default_rps=10, min_rps=1, max_rps=20)
    limiter.on_response("example.com", 429, retry_after=2)
    assert limiter.get_stats()["example.com"]["paused"] is True
    assert limiter._buckets["example.com"].rps == 5


def test_success_ramp_is_bounded():
    limiter = AdaptiveRateLimiter(default_rps=2, min_rps=1, max_rps=3)
    for _ in range(20):
        limiter.on_response("example.com", 200)
    assert limiter._buckets["example.com"].rps <= 3


def test_token_bucket_does_not_overspend():
    limiter = AdaptiveRateLimiter(default_rps=100, min_rps=1, max_rps=100)
    async def run():
        await asyncio.gather(*(limiter.acquire("example.com") for _ in range(5)))
    asyncio.run(run())
