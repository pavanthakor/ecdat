"""must_fire: py-hmac-md5."""
import hashlib
import hmac

tag = hmac.new(mac_key, message, hashlib.md5).digest()
