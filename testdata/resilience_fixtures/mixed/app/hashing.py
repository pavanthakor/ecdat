import hashlib


def legacy_etag(body: bytes) -> str:
    return hashlib.md5(body).hexdigest()
