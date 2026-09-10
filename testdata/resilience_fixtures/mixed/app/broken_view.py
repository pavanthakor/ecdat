import hashlib

# Deliberately unparseable. The unbalanced brackets at the end make semgrep's
# Python parser reject the WHOLE file (STEP 0, ADR-0033) -- a gentler break,
# such as `def f(:` over a valid body, it silently recovers from instead. So
# the SHA-1 below is real crypto ECDAT cannot see, and it must surface as a
# coverage gap: never as silence, and never as a clean file.


def seen_by_nobody():
    return hashlib.sha1(b"never seen")


def half_written(:
    return (((
