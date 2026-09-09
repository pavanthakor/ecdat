"""must_fire: py-hashlib-sha512 -- safe control."""
import hashlib

digest = hashlib.sha512(b"payload").hexdigest()
