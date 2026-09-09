"""must_fire: py-hardcoded-iv -- a fixed IV, which defeats CBC/CTR entirely."""
from Crypto.Cipher import AES

cipher = AES.new(session_key, AES.MODE_CBC, iv=b"SECRETSENTINEL16")
