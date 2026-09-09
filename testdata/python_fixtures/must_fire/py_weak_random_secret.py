"""must_fire: py-weak-random-secret -- Mersenne Twister reached for as a CSPRNG."""
import random

session_token = random.random()
api_key = random.randint(0, 2**64)
