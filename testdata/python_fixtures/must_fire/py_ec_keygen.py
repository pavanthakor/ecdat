"""must_fire: py-ec-keygen -- curve captured, usage stays unknown at keygen."""
from Crypto.PublicKey import ECC
from cryptography.hazmat.primitives.asymmetric import ec

agreement_key = ec.generate_private_key(ec.SECP256R1())

chosen_curve = ec.SECP384R1()
configured_key = ec.generate_private_key(chosen_curve)

legacy_key = ECC.generate(curve="P-256")
