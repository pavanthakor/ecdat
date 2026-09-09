"""must_fire: py-des3."""
from Crypto.Cipher import DES3

cipher = DES3.new(session_key, DES3.MODE_CBC, nonce)
