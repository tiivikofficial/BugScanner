"""Adaptive, server-friendly rate limiting.

The limiter intentionally reacts to server back-pressure instead of trying to
bypass it.  Retry-After is honoured when present and successful traffic only
ramps up slowly.
"""

import asyncio
import time
from dataclasses import dataclass, field
from collections import defaultdict
from rich.console import Console

console = Console()


@dataclass
class TokenBucket:
    rps: float
    tokens: float = field(init=False)
    last_refill: float = field(init=False)
    lock: asyncio.Lock = field(init=False)

    def __post_init__(self):
        self.rps = max(float(self.rps), 0.1)
        self.tokens = self.rps
        self.last_refill = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self):
        async with self.lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.last_refill
                self.tokens = min(self.rps, self.tokens + elapsed * self.rps)
                self.last_refill = now

                if self.tokens >= 1:
                    self.tokens -= 1
                    return

                wait = (1 - self.tokens) / self.rps
                await asyncio.sleep(wait)


class AdaptiveRateLimiter:
    """Per-domain token buckets with explicit back-pressure handling."""

    def __init__(
        self,
        default_rps: float = 10.0,
        min_rps: float = 1.0,
        max_rps: float = 50.0,
        backoff_multiplier: float = 2.0,
        pause_on_503: int = 30,
    ):
        if min_rps <= 0 or max_rps < min_rps or default_rps <= 0:
            raise ValueError("Invalid rate-limit bounds")
        if backoff_multiplier <= 1:
            raise ValueError("backoff_multiplier must be greater than 1")

        self.default_rps = min(float(default_rps), float(max_rps))
        self.min_rps = float(min_rps)
        self.max_rps = float(max_rps)
        self.backoff_multiplier = float(backoff_multiplier)
        self.pause_on_503 = max(0, int(pause_on_503))

        self._buckets: dict[str, TokenBucket] = {}
        self._success_streak: dict[str, int] = defaultdict(int)
        self._paused_until: dict[str, float] = {}

    def _get_bucket(self, domain: str) -> TokenBucket:
        if domain not in self._buckets:
            self._buckets[domain] = TokenBucket(rps=self.default_rps)
        return self._buckets[domain]

    async def acquire(self, domain: str):
        """Wait until a request to *domain* is permitted."""
        if domain in self._paused_until:
            remaining = self._paused_until[domain] - time.monotonic()
            if remaining > 0:
                console.print(
                    f"[yellow]⏸  {domain} — {remaining:.0f}s back-pressure pause[/yellow]"
                )
                await asyncio.sleep(remaining)
            self._paused_until.pop(domain, None)

        await self._get_bucket(domain).acquire()

    def on_response(
        self,
        domain: str,
        status_code: int,
        retry_after: float | None = None,
    ):
        """Update limits from a response, honouring Retry-After when supplied."""
        bucket = self._get_bucket(domain)

        if status_code == 429:
            new_rps = max(self.min_rps, bucket.rps / self.backoff_multiplier)
            bucket.rps = new_rps
            self._success_streak[domain] = 0
            pause = max(0.0, retry_after or 0.0)
            if pause:
                self._paused_until[domain] = max(
                    self._paused_until.get(domain, 0.0), time.monotonic() + pause
                )
            console.print(
                f"[red]⚡ 429 — {domain} RPS → {new_rps:.1f}"
                f"{f', pause {pause:.0f}s' if pause else ''}[/red]"
            )

        elif status_code == 503:
            pause = max(float(self.pause_on_503), retry_after or 0.0)
            self._paused_until[domain] = max(
                self._paused_until.get(domain, 0.0), time.monotonic() + pause
            )
            self._success_streak[domain] = 0
            console.print(
                f"[red]🛑 503 — {domain} paused for {pause:.0f}s[/red]"
            )

        elif status_code < 400:
            self._success_streak[domain] += 1
            if self._success_streak[domain] % 20 == 0:
                new_rps = min(self.max_rps, bucket.rps * 1.2)
                if new_rps > bucket.rps:
                    bucket.rps = new_rps
                    console.print(
                        f"[green]📈 {domain} RPS → {new_rps:.1f}[/green]"
                    )

    def get_stats(self) -> dict:
        return {
            domain: {
                "current_rps": round(bucket.rps, 2),
                "success_streak": self._success_streak.get(domain, 0),
                "paused": self._paused_until.get(domain, 0) > time.monotonic(),
            }
            for domain, bucket in self._buckets.items()
        }
