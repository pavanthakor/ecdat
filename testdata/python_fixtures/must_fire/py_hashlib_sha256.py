"""must_fire: py-hashlib-sha256 -- the safe control; detection must not miss it."""
import hashlib

digest = hashlib.sha256(b"payload").hexdigest()
