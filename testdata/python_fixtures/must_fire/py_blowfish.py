"""must_fire: py-blowfish."""
from Crypto.Cipher import Blowfish

cipher = Blowfish.new(session_key, Blowfish.MODE_CBC, nonce)
