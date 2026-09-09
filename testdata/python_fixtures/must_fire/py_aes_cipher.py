"""must_fire: py-aes-cipher.

ECB and GCM must come out as distinguishable params.mode on separate findings,
and the pycryptodome spelling must be caught alongside the cryptography one.
"""
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

gcm = Cipher(algorithms.AES(session_key), modes.GCM(nonce))
ecb = Cipher(algorithms.AES(session_key), modes.ECB())
ctr = Cipher(algorithms.AES(session_key), modes.CTR(nonce))

legacy_cbc = AES.new(session_key, AES.MODE_CBC, nonce)
