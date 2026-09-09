"""must_fire: py-hardcoded-cipher-key -- a key literal handed straight to AES."""
from Crypto.Cipher import AES

cipher = AES.new(b"SECRETSENTINEL16", AES.MODE_CBC, nonce)
