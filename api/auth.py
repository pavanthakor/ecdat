"""API keys: who may call the ECDAT API, and as what (ADR-0035).

A key is a bearer token -- ``Authorization: Bearer ecdat_<43 url-safe chars>``,
256 bits from :mod:`secrets`. The server never holds a key, only its SHA-256
digest, in a JSON file named by ``ECDAT_API_KEYS`` (default
``~/.config/ecdat/api-keys.json``: outside any checkout, mode 0600). So the
secret is provisioned by the operator with ``ecdat api-key create``; it is not
in the source and it is not in the repository.

**Why a plain digest and not a slow password hash.** The tokens are 256-bit
random values, not passwords a person chose. There is no dictionary to try, so
a deliberately slow hash would protect nothing and would slow every request.

**The check is local.** Read the file, digest the presented token, compare it
against EVERY configured digest with :func:`hmac.compare_digest` -- no early
exit, so the time taken does not say which key matched or how close a guess
came. No identity provider, no network call, nothing to reach from an
air-gapped host. The file is read on every request, so a revoke takes effect on
the next one.

**Two roles, ordered.** ``viewer`` reads. ``admin`` can also trigger work that
reads a target -- scans, system scans, fix passes -- and read the verified
patches. The route-by-route policy is in ``api/app.py``; a structural test in
tests/test_api_auth.py fails on any route that declares neither guard.

**Fail closed.** No key file means nobody gets in (401, with the remedy). A key
file that exists but cannot be used is a 503 for everyone: "the file is broken"
must never degrade into "the file is empty", and it certainly must never
degrade into "no auth".
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, get_args

from fastapi import Depends, HTTPException, Request, status

__all__ = [
    "ENV_API_KEYS",
    "ROLES",
    "Admin",
    "ApiKey",
    "KeyExistsError",
    "KeyFileError",
    "Principal",
    "Role",
    "UnknownKeyError",
    "Viewer",
    "add_key",
    "authenticate",
    "current_principal",
    "digest",
    "keys_path",
    "load_keys",
    "require_admin",
    "require_viewer",
    "revoke_key",
]

ENV_API_KEYS = "ECDAT_API_KEYS"
#: Marks a string as an ECDAT key in a log or a paste buffer. Not a secret.
TOKEN_PREFIX = "ecdat_"  # noqa: S105 - a label on every token, not a secret
FILE_VERSION = 1

Role = Literal["viewer", "admin"]
ROLES: tuple[Role, ...] = get_args(Role)
_RANK: dict[str, int] = {"viewer": 0, "admin": 1}

REMEDY = (
    "Keys are issued on the server with "
    "`ecdat api-key create --name <who> --role viewer|admin`."
)


class KeyFileError(RuntimeError):
    """The key file exists but cannot be used. The API fails CLOSED on it."""


class KeyExistsError(ValueError):
    """A key with that name is already issued."""


class UnknownKeyError(LookupError):
    """No key with that name to revoke."""


@dataclass(frozen=True, slots=True)
class ApiKey:
    """One issued key, as the file holds it: a name, a role, a digest."""

    name: str
    role: Role
    sha256: str
    created_at: str


@dataclass(frozen=True, slots=True)
class Principal:
    """Who a request is: the NAME of the key it presented, and its role."""

    name: str
    role: Role


# ---------------------------------------------------------------------------
# The key file
# ---------------------------------------------------------------------------


def keys_path() -> Path:
    """Where the key file is: ``$ECDAT_API_KEYS``, else the user's config dir."""
    configured = os.environ.get(ENV_API_KEYS)
    if configured:
        return Path(configured).expanduser()
    config_home = os.environ.get("XDG_CONFIG_HOME")
    base = Path(config_home) if config_home else Path.home() / ".config"
    return base / "ecdat" / "api-keys.json"


def digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _entry(raw: object, index: int, path: Path) -> ApiKey:
    if isinstance(raw, dict):
        name, role, sha = raw.get("name"), raw.get("role"), raw.get("sha256")
        if (
            isinstance(name, str)
            and name
            and role in ROLES
            and isinstance(sha, str)
            and len(sha) == 64
        ):
            return ApiKey(
                name=name,
                role=role,  # checked against ROLES above
                sha256=sha,
                created_at=str(raw.get("created_at", "")),
            )
    raise KeyFileError(
        f"entry {index} of the API key file {path} is malformed: it needs a "
        f"name, a role in {list(ROLES)} and a 64-character sha256"
    )


def load_keys(path: Path | None = None) -> list[ApiKey]:
    """Every configured key; ``[]`` when the file does not exist.

    A file that exists but is not a key file -- bad JSON, a wrong shape, an
    unknown role -- raises :class:`KeyFileError` rather than reading as empty.
    Skipping a malformed entry could silently drop the only admin.
    """
    target = path or keys_path()
    try:
        text = target.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise KeyFileError(f"cannot read the API key file {target}: {exc}") from exc
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise KeyFileError(
            f"the API key file {target} is not valid JSON: {exc}"
        ) from exc
    entries = document.get("keys") if isinstance(document, dict) else None
    if not isinstance(entries, list):
        raise KeyFileError(f"the API key file {target} has no 'keys' list")
    return [_entry(raw, index, target) for index, raw in enumerate(entries)]


def _write_keys(keys: Sequence[ApiKey], path: Path) -> None:
    """Replace the key file atomically, readable by its owner only.

    ``mkstemp`` creates the file 0600 before a byte is written, so there is no
    window in which the digests are world-readable; ``os.replace`` makes the
    swap atomic, so a reader never sees half a file.
    """
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    document = {"version": FILE_VERSION, "keys": [asdict(key) for key in keys]}
    handle, temporary = tempfile.mkstemp(
        dir=path.parent, prefix=".api-keys.", suffix=".tmp"
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
        Path(temporary).chmod(0o600)
        Path(temporary).replace(path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def add_key(name: str, role: Role, path: Path | None = None) -> str:
    """Issue a key. Stores its digest; returns the token -- the ONLY copy."""
    if role not in ROLES:
        raise ValueError(f"unknown role {role!r}; expected one of {list(ROLES)}")
    name = name.strip()
    if not name:
        raise ValueError("a key needs a non-empty name")
    target = path or keys_path()
    keys = load_keys(target)
    if any(key.name == name for key in keys):
        raise KeyExistsError(
            f"a key named {name!r} already exists in {target}; revoke it first "
            f"or choose another name"
        )
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    issued = ApiKey(
        name=name,
        role=role,
        sha256=digest(token),
        created_at=datetime.now(tz=UTC).isoformat(timespec="seconds"),
    )
    _write_keys([*keys, issued], target)
    return token


def revoke_key(name: str, path: Path | None = None) -> None:
    target = path or keys_path()
    keys = load_keys(target)
    kept = [key for key in keys if key.name != name]
    if len(kept) == len(keys):
        raise UnknownKeyError(f"no key named {name!r} in {target}")
    _write_keys(kept, target)


def authenticate(token: str, keys: Sequence[ApiKey]) -> Principal | None:
    """The key ``token`` belongs to, or ``None``.

    Compares against EVERY key, with no early exit on a match, so the time
    taken is the same whichever key -- or none -- matches.
    """
    presented = digest(token)
    matched: ApiKey | None = None
    for key in keys:
        if hmac.compare_digest(presented, key.sha256) and matched is None:
            matched = key
    return None if matched is None else Principal(name=matched.name, role=matched.role)


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _bearer_token(header: str) -> str | None:
    scheme, _, token = header.strip().partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token or any(c.isspace() for c in token):
        return None
    return token


def current_principal(request: Request) -> Principal:
    """Authenticate the request, or refuse it with a body that says why."""
    path = keys_path()
    try:
        keys = load_keys(path)
    except KeyFileError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"{exc}. Every request is refused until it is fixed (ADR-0035).",
        ) from exc
    if not keys:
        raise _unauthorized(f"no API keys are configured on this server. {REMEDY}")

    header = request.headers.get("authorization")
    if header is None:
        raise _unauthorized(
            f"missing credential: send `Authorization: Bearer <api key>`. {REMEDY}"
        )
    token = _bearer_token(header)
    if token is None:
        raise _unauthorized(
            "malformed credential: expected `Authorization: Bearer <api key>`."
        )
    principal = authenticate(token, keys)
    if principal is None:
        raise _unauthorized(
            "invalid credential: no configured key matches this token "
            "(it may have been revoked)."
        )
    return principal


def require_viewer(
    principal: Annotated[Principal, Depends(current_principal)],
) -> Principal:
    """Any valid key. Every data route depends on this or on ``require_admin``."""
    return principal


def require_admin(
    principal: Annotated[Principal, Depends(current_principal)],
) -> Principal:
    """A valid key whose role is ``admin``; a viewer is 403, not 401."""
    if _RANK[principal.role] < _RANK["admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"forbidden: the key {principal.name!r} has role "
                f"{principal.role!r}; this route needs 'admin'."
            ),
        )
    return principal


#: Route parameter types, for routes that need to know WHO asked.
Viewer = Annotated[Principal, Depends(require_viewer)]
Admin = Annotated[Principal, Depends(require_admin)]
