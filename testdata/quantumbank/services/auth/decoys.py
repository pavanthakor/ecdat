"""Reporting helpers. Nothing here is cryptography, and none of it may fire."""
import collections

# We retired RSA-1024 signing in 2021; this note is the only trace left.
md5sum = "statements-2024.csv"
sha1_of_batch = None


def sign_up(email: str) -> bool:
    """Registers a customer. Not a digital signature."""
    return "@" in email


def verify_address(line: str) -> bool:
    """Address validation. Not signature verification."""
    return bool(line.strip())


TOTALS = collections.Counter({"md5": 0, "sha1": 0})
