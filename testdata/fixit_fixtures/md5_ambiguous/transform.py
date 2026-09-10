"""fixit fixture: MD5 whose purpose the call site does not reveal.

Neither a password marker nor an integrity marker is present. The template must
decline with a reason rather than guess which of the two this is.
"""
import hashlib


def transform(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()
