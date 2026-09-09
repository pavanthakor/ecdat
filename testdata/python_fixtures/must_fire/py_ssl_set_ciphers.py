"""must_fire: py-ssl-set-ciphers."""
import ssl

context = ssl.create_default_context()
context.set_ciphers("ECDHE-RSA-AES128-SHA:RC4-SHA")
