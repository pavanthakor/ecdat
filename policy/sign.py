"""Ed25519 detached signatures over policy packs.

A pack decides what an organisation is told about its own cryptography. Anyone
who can edit one unnoticed can turn a Critical into a Low, and the change is a
two-character diff in a YAML file that nobody re-reads. Signing is what makes
that edit visible.

The signature is DETACHED -- ``quantum.yaml`` sits beside ``quantum.yaml.sig``
-- so the pack stays a plain, readable, diffable YAML file. It covers the exact
bytes of the pack, so reformatting invalidates it too; that is intended, since
"only whitespace changed" is a claim a reviewer should have to make explicitly
by re-signing.

DEV KEYS. The keypair under ``policy/keys/dev/`` is committed to this
repository. It is a DEVELOPMENT key: its private half is public by definition,
so a signature made with it proves only that a pack was built by this repo's
tooling, not that anyone approved it. Production key management -- an offline
signing key, a published verification key, and a release process that uses them
-- is deferred and recorded in ADR-0007 and PUNCHLIST.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

__all__ = [
    "SIGNATURE_SUFFIX",
    "generate_keypair",
    "load_private_key",
    "load_public_key",
    "sign_file",
    "signature_path",
    "verify_file",
]

SIGNATURE_SUFFIX = ".sig"

#: Written into the committed dev private key so nobody mistakes it for a real
#: one on a casual `cat`.
_DEV_KEY_BANNER = (
    "# ECDAT DEVELOPMENT SIGNING KEY -- NOT SECRET, NOT FOR PRODUCTION.\n"
    "# This private key is committed to a public repository on purpose, so\n"
    "# that `make check` can verify the shipped packs out of the box. A\n"
    "# signature made with it proves the pack was built by this repo's\n"
    "# tooling and NOTHING about who approved it. See ADR-0007.\n"
)


def signature_path(pack_path: Path | str) -> Path:
    """``quantum.yaml`` -> ``quantum.yaml.sig``."""
    path = Path(pack_path)
    return path.with_name(path.name + SIGNATURE_SUFFIX)


def generate_keypair(private_path: Path | str, public_path: Path | str) -> None:
    """Write a fresh Ed25519 keypair. Overwrites, so callers must be sure."""
    private = Path(private_path)
    public = Path(public_path)
    private.parent.mkdir(parents=True, exist_ok=True)
    public.parent.mkdir(parents=True, exist_ok=True)

    key = ed25519.Ed25519PrivateKey.generate()
    private.write_bytes(
        _DEV_KEY_BANNER.encode("ascii")
        + key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    private.chmod(0o600)
    public.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def load_private_key(path: Path | str) -> ed25519.Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise TypeError(f"{path} is not an Ed25519 private key")
    return key


def load_public_key(path: Path | str) -> ed25519.Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise TypeError(f"{path} is not an Ed25519 public key")
    return key


def sign_file(pack_path: Path | str, private_key_path: Path | str) -> Path:
    """Sign a pack's exact bytes; write the detached signature beside it."""
    path = Path(pack_path)
    key = load_private_key(private_key_path)
    destination = signature_path(path)
    destination.write_bytes(key.sign(path.read_bytes()))
    return destination


def verify_file(pack_path: Path | str, public_key_path: Path | str) -> None:
    """Raise unless ``pack_path`` carries a valid signature for its bytes.

    Imported lazily by the engine's error type so this module stays free of
    policy imports; the engine translates both failures into
    ``PackSignatureError``.
    """
    from policy.engine import PackSignatureError

    path = Path(pack_path)
    signature = signature_path(path)
    if not signature.is_file():
        raise PackSignatureError(
            f"{path} has no signature at {signature}. Policy packs must be "
            "signed: run `make sign-packs`, or pass dev=True to skip "
            "verification for local development only."
        )

    try:
        load_public_key(public_key_path).verify(
            signature.read_bytes(), path.read_bytes()
        )
    except InvalidSignature as exc:
        raise PackSignatureError(
            f"{path} failed signature verification against {public_key_path}. "
            "The pack has been modified since it was signed, or it was signed "
            "with a different key. Refusing to score with it."
        ) from exc
    except (OSError, ValueError, TypeError) as exc:
        raise PackSignatureError(
            f"{path}: signature could not be checked: {exc}"
        ) from exc


def sign_all(pack_dir: Path | str, private_key_path: Path | str) -> list[Path]:
    """Sign every pack in a directory. Backs `make sign-packs`."""
    written = [
        sign_file(pack, private_key_path)
        for pack in sorted(Path(pack_dir).glob("*.yaml"))
    ]
    return written


def main() -> int:  # pragma: no cover - exercised via `make sign-packs`
    from policy.engine import DEFAULT_PACK_DIR, DEFAULT_PUBLIC_KEY

    private = DEFAULT_PUBLIC_KEY.with_suffix(".key")
    if not private.is_file():
        generate_keypair(private, DEFAULT_PUBLIC_KEY)
        print(f"generated DEV keypair: {private}, {DEFAULT_PUBLIC_KEY}")

    for path in sign_all(DEFAULT_PACK_DIR, private):
        print(f"signed {path.with_suffix('')} -> {path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
