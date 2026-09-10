"""CONST-PROP: the algorithm is named by a variable, not at the call site.

`py-hashlib-md5` is written against `hashlib.new("md5", ...)`. Here the digest
is selected through a variable whose value is a literal two lines up, and
through a module-level constant -- semgrep's constant propagation is what lets
the pattern still match.

This is the config-driven shape that shows up in real code: a digest chosen by
a settings value that happens to have a literal default.
"""

import hashlib

FALLBACK_DIGEST = "md5"


def digest_from_local(data: bytes) -> str:
    algo = "md5"
    return hashlib.new(algo, data).hexdigest()


def digest_from_module_constant(data: bytes) -> str:
    return hashlib.new(FALLBACK_DIGEST, data).hexdigest()
