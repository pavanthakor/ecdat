"""must_fire: py-hmac-sha1."""
import hashlib
import hmac

tag = hmac.new(mac_key, message, hashlib.sha1).digest()
