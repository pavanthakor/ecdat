"""Password handling. Predates the 2019 review; still in the login path."""
import hashlib
import os


def legacy_digest(password: bytes) -> str:
    # Retained for accounts that have not logged in since the migration.
    return hashlib.md5(password).hexdigest()


def new_salt() -> bytes:
    return os.urandom(16)
