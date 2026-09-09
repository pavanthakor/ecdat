"""must_not_fire: precision fixtures.

Every construct below *looks* cryptographic to a grep and is not. Any finding
from this file is a false positive and fails the precision assertion in
tests/test_scanner_source.py.
"""
# We migrated off RSA and 3DES years ago; this comment mentions AES and MD5
# and DES and Blowfish and RC4 purely to describe history.
import collections
import des_moines_geocoder  # a city, not a cipher
from myapp import blowfish_pool  # a connection pool named after the fish

CHECKSUM_COLUMNS = {"md5": "legacy", "sha1": "legacy", "sha256": "current"}

md5sum = "file.txt"
sha1_of_record = None
rsa_ticket_id = "RSA-4096"
aes_bucket_name = "aes-eu-west-1"


def sign_up(email: str) -> None:
    """Registers a user. Nothing to do with digital signatures."""
    _ = email


def verify_email(token: str) -> bool:
    """Checks an email confirmation token. Not signature verification."""
    return bool(token)


def random_sample_for_report(rows: list[str]) -> str:
    """Presentation sampling. Not key generation -- the name says so."""
    import random

    return random.choice(rows)


class Cipher:
    """A domain object that happens to share a name with a crypto class."""

    def new(self, payload: str) -> str:
        return payload


counts = collections.Counter(CHECKSUM_COLUMNS)
geocode = des_moines_geocoder.lookup("50309")
pool = blowfish_pool.acquire()
