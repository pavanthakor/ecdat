"""fixit fixture: MD5 used to checksum an uploaded artefact.

Integrity of a build artefact against accidental corruption -- no secret, no
password, no signature. This is the ONE context in which the md5-to-sha256
template is allowed to fire.
"""
import hashlib


def artefact_checksum(payload: bytes) -> str:
    digest = hashlib.md5(payload)
    return digest.hexdigest()
