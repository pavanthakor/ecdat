"""must_fire: py-hashlib-sha384 -- safe control."""
import hashlib

digest = hashlib.sha384(b"payload").hexdigest()
