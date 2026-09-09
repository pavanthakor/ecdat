"""must_fire: py-pem-private-key.

The body is not a real key -- it is filler that merely has the shape of one.
The point of the fixture is the redaction assertion: whatever sits between the
PEM banners must never reach a Finding snippet.
"""

SIGNING_KEY = """-----BEGIN RSA PRIVATE KEY-----
NOTAREALKEYNOTAREALKEYNOTAREALKEYNOTAREALKEYNOTAREALKEYNOTAREALK
SECRETSENTINELMUSTNEVERAPPEARINANYFINDINGSNIPPETANYWHEREATALL000
-----END RSA PRIVATE KEY-----
"""
