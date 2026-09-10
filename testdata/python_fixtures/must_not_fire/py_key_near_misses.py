"""must_not_fire (ADR-0034): near misses.

Each fails exactly ONE of the candidate rule's gates -- name, length, entropy --
and must not fire.
"""

# Right name, right length, no entropy.
REPEATING_KEY = "deadbeefdeadbeefdeadbeefdeadbeef"

# Right name, random, 31 characters: under the 32-character bar.
SHORT_HEX_KEY = "c3eb65549b67a01ddea161edcbcad6c"

# Random and 64 characters, but nothing in the NAME says key: a digest.
RELEASE_CHECKSUM = "bf18000d8dcc897b10d2793f2424df1fb5a2a76b3365380b70f62e6e1cc41aed"
