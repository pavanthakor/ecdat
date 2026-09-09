"""must_fire: py-des."""
from Crypto.Cipher import DES

cipher = DES.new(session_key, DES.MODE_ECB)
