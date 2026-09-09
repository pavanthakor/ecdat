"""must_fire: py-os-urandom -- the safe control; detection must not miss it."""
import os

nonce = os.urandom(16)
