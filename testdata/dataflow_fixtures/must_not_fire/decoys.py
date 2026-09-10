"""Dataflow that MUST NOT produce a single finding.

The precision case for taint: `random.random()` is entirely legitimate, and a
rule that fired on every use of it would be noise an operator learns to ignore.
What makes the taint rule safe is the SINK, not the source -- none of these
values reaches one.
"""

import os
import random


def monte_carlo(trials: int) -> float:
    """A simulation. random.random() with no cryptographic sink anywhere."""
    inside = 0
    for _ in range(trials):
        x, y = random.random(), random.random()
        if x * x + y * y <= 1.0:
            inside += 1
    return 4.0 * inside / trials


def backoff_delay(attempt: int) -> float:
    """Jitter. Also not a key, and it reaches no cipher."""
    jitter = random.random()
    return min(2**attempt, 60) + jitter


def sample_banner(banners: list[str]) -> str:
    """Picking a display string is not key generation."""
    return banners[int(random.random() * len(banners))]


def page_size() -> int:
    """An env read that has nothing to do with cryptography.

    The configurability rule must be scoped to CRYPTO sinks: an env-sourced
    value is only interesting where it selects an algorithm or a key size.
    """
    return int(os.environ.get("PAGE_SIZE", "50"))


def build_label(tenant: str) -> bytes:
    """Concatenation that is not key material -- it reaches no cipher."""
    return b"tenant-" + tenant.encode() + b"-label"


def sign_with_an_unlisted_algorithm(claims: dict, key: str) -> str:
    """A JOSE algorithm none of the four family rules claims.

    EdDSA is a real `alg` value (RFC 8037) and no rule in this pack covers it.
    The propagation-aware classification must not become a catch-all: a rule
    that fired here would be reporting an algorithm it has no note for.
    """
    import jwt

    alg = "EdDSA"
    return jwt.encode(claims, key, algorithm=alg)
