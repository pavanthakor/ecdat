"""The structural redaction guard: no secret key material in evidence (ADR-0036).

Every Finding is built through ``core/schema.py``, and every CBOM through the
normaliser. Both call this module. So "a snippet never carries key bytes" no
longer depends on each scanner remembering to redact: a scanner that forgets
is caught here, before anything is stored. The scanners' own redaction stays,
as defence in depth -- they are stricter than this, and should be.

It targets KEY MATERIAL, not entropy. Four rules, from the most structural to
the most contextual:

1. **Private-key armour** -- PEM (PKCS#1, PKCS#8, SEC1, encrypted), OpenSSH,
   PGP and PuTTY private keys. The WHOLE text is replaced: the body can follow
   the banner on the same line, the next one, or inside an escaped string, and
   partially scrubbing an armoured block is how one line leaks.
2. **DER private-key structure**, however it is spelled -- base64 or
   base64url, hex (contiguous or separated), ``\\x`` escapes, a byte array, or
   raw bytes decoded into the text. A run is key material if it DECODES to one:
   a SEQUENCE whose first element is INTEGER 0 or 1 followed by an INTEGER,
   SEQUENCE or OCTET STRING (PKCS#1 RSA, DSA, PKCS#8 v1 and v2, SEC1 EC), an
   EncryptedPrivateKeyInfo (PKCS#5/#12 PBE), a PKCS#12 PFX, or an
   ``openssh-key-v1`` body. A certificate, a SubjectPublicKeyInfo and an
   RSAPublicKey never match -- their first element is a SEQUENCE, or an INTEGER
   far longer than one byte. Only the run is replaced.
3. **A secret-named, high-entropy literal** -- ADR-0034's discipline. When an
   identifier OUTSIDE the string literals names a secret (``secret``,
   ``password``, ``passphrase``, ``credential``, or ``key`` without a word that
   makes it public or metadata: ``public``, ``cert``, ``fingerprint``,
   ``size``, ``id``, ``path``, ``digest``...), a quoted literal or an assigned
   value of 32+ hex/base64 characters with real entropy is replaced. An
   algorithm name, an identifier-shaped string, and a value that decodes to a
   PUBLIC DER structure are kept.
4. **Key context** -- a finding its own scanner called key material
   (``asset_type == "key"``, unless it is a public key, or ADR-0034's
   ``candidate`` flag). The scanner has already said this line is about a key,
   so every literal of 8+ characters that is not an algorithm name goes, as do
   long bare key-shaped tokens, byte arrays and escape runs.

Rules 1-2 apply to every free-text field of evidence (locator, detail, snippet)
and to string params. Rules 3-4 apply to snippets only: the one field meant to
hold a line of somebody else's text.

**Not covered, and stated** (PUNCHLIST): an UNNAMED literal on a line matched
by a rule that is not about the key -- ``jwt.encode(claims, "s3cr3t...")``
reported by the JWT rule. Nothing in that text says the literal is a key, and
catching it would mean redacting every opaque literal, hash digests included.
The source scanner's own opaque-literal net covers it.

Every redaction is logged -- which rule, which field, where -- and never what
was redacted. On a scan by the shipped scanners the log is silent; an entry
means a scanner left key material in its evidence.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from core.logs import get_logger

__all__ = [
    "EVENT",
    "REDACTED",
    "REDACTED_VALUE",
    "is_key_context",
    "is_private_key_der",
    "redact_evidence",
    "redact_key_context",
    "redact_params",
]

#: Replaces a whole text. The same string the scanners have always used.
REDACTED = "<redacted key material>"
#: Replaces one value inside a text that is otherwise worth keeping.
REDACTED_VALUE = "<redacted>"

#: The log event, and the rule names it reports.
EVENT = "key_material_redacted"
ARMOUR = "private-key-armour"
DER = "der-private-key"
SECRET_NAME = "secret-name"  # noqa: S105 - a rule's name, not a secret
KEY_CONTEXT = "key-context"

_log = get_logger("core.redaction")


# ---------------------------------------------------------------------------
# Rule 1 -- private-key armour
# ---------------------------------------------------------------------------

_ARMOUR = re.compile(
    r"-----\s*(?:BEGIN|END)\s+[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?\s*-----"
    r"|PuTTY-User-Key-File-\d+\s*:"
    r"|\bPrivate-Lines\s*:\s*\d+"
)


# ---------------------------------------------------------------------------
# Rule 2 -- DER private-key structure
# ---------------------------------------------------------------------------

#: 1.2.840.113549.1.5 (PKCS#5 PBES1/PBES2) and 1.2.840.113549.1.12.1 (PKCS#12
#: PBE): the algorithm of an EncryptedPrivateKeyInfo. 1.2.840.113549.1.7.1
#: (PKCS#7 data): the authSafe of a PKCS#12 PFX.
_PKCS5_PBE = bytes.fromhex("2a864886f70d0105")
_PKCS12_PBE = bytes.fromhex("2a864886f70d010c01")
_PKCS7_DATA = bytes.fromhex("2a864886f70d010701")
_OPENSSH_MAGIC = b"openssh-key-v1\x00"

#: Below this a SEQUENCE cannot hold a private key: the smallest real one,
#: Ed25519 in PKCS#8, has 46 bytes of content.
_MIN_KEY_CONTENT = 32

_B64_RUN = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{40,}={0,2}")
_HEX_RUN = re.compile(r"(?<![0-9A-Za-z])(?:0[xX])?[0-9A-Fa-f]{64,}(?![0-9A-Za-z])")
_HEX_SEPARATED = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}[:\s]){31,}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])"
)
_ESCAPES = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){16,}")
_ARRAY_ITEM = r"(?:\(byte\)\s*)?(?:0[xX][0-9A-Fa-f]{1,2}|\d{1,3})(?![\w.])"
_BYTE_ARRAY = re.compile(rf"(?<![\w.]){_ARRAY_ITEM}(?:\s*,\s*{_ARRAY_ITEM}){{15,}}")
#: Raw DER decoded straight into the text (latin-1): a SEQUENCE header, then
#: INTEGER 0 or 1, then INTEGER / SEQUENCE / OCTET STRING.
_RAW_DER = re.compile(
    "0(?:\x81[\x80-\xff]|\x82[\x00-\xff]{2}|\x83[\x00-\xff]{3}|[\x20-\x7f])"
    "\x02\x01[\x00\x01][\x02\x30\x04]"
)
_RAW_OPENSSH = _OPENSSH_MAGIC.decode("ascii")


def _der_header(blob: bytes) -> tuple[int, int] | None:
    """``(declared length, offset of the contents)`` of a SEQUENCE, or None."""
    if len(blob) < 2 or blob[0] != 0x30:
        return None
    first = blob[1]
    if first < 0x80:
        return first, 2
    count = first & 0x7F
    if not 1 <= count <= 3 or len(blob) < 2 + count:
        return None
    return int.from_bytes(blob[2 : 2 + count], "big"), 2 + count


def is_private_key_der(blob: bytes) -> bool:
    """Whether ``blob`` begins with a private key's DER structure.

    Only the first few dozen bytes are read, so a prefix is enough -- the first
    line of a PEM body decodes to one.
    """
    if blob.startswith(_OPENSSH_MAGIC):
        return True
    header = _der_header(blob)
    if header is None:
        return False
    length, start = header
    if length < _MIN_KEY_CONTENT:
        return False
    head = blob[start : start + 4]
    if head[:3] in (b"\x02\x01\x00", b"\x02\x01\x01") and head[3:4] in (
        b"\x02",
        b"\x30",
        b"\x04",
    ):
        return True  # PKCS#1 RSA, DSA, PKCS#8 v1/v2, SEC1 EC
    window = blob[start : start + 40]
    if head[:1] == b"\x30" and (_PKCS5_PBE in window or _PKCS12_PBE in window):
        return True  # EncryptedPrivateKeyInfo
    return head[:3] == b"\x02\x01\x03" and _PKCS7_DATA in window  # PKCS#12 PFX


def _is_public_der(blob: bytes) -> bool:
    """A certificate, SubjectPublicKeyInfo or RSAPublicKey -- complete."""
    header = _der_header(blob)
    if header is None or is_private_key_der(blob):
        return False
    length, start = header
    return start + length == len(blob) and blob[start : start + 1] in (b"\x30", b"\x02")


def _from_base64(run: str) -> bytes | None:
    text = run.rstrip("=")
    if "-" in text or "_" in text:
        text = text.replace("-", "+").replace("_", "/")
    if len(text) % 4 == 1:
        # One stray character cannot complete a quantum; the rest still can.
        text = text[:-1]
    # Re-padded, not truncated: a complete public key must decode COMPLETE, or
    # the "this is a public structure" check below would see it one byte short.
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def _from_hex(run: str) -> bytes | None:
    digits = re.sub(r"[\s:]", "", run)
    if digits[:2] in ("0x", "0X"):
        digits = digits[2:]
    digits = digits[: len(digits) - len(digits) % 2]
    try:
        return bytes.fromhex(digits)
    except ValueError:
        return None


def _from_escapes(run: str) -> bytes | None:
    return bytes(int(pair, 16) for pair in re.findall(r"\\x([0-9A-Fa-f]{2})", run))


def _from_array(run: str) -> bytes | None:
    values = [
        int(item, 16) if item[:2].lower() == "0x" else int(item)
        for item in re.findall(r"0[xX][0-9A-Fa-f]{1,2}|\d{1,3}", run)
    ]
    if any(value > 0xFF for value in values):
        return None
    return bytes(values)


#: Most specific first: once a run is replaced, a broader pattern cannot
#: re-read it.
_DER_RUNS: tuple[tuple[re.Pattern[str], Callable[[str], bytes | None]], ...] = (
    (_ESCAPES, _from_escapes),
    (_BYTE_ARRAY, _from_array),
    (_HEX_SEPARATED, _from_hex),
    (_HEX_RUN, _from_hex),
    (_B64_RUN, _from_base64),
)


def _redact_der(text: str) -> tuple[str, bool]:
    if _RAW_DER.search(text) or _RAW_OPENSSH in text:
        return REDACTED, True
    hit = False

    def replacer(
        decode: Callable[[str], bytes | None],
    ) -> Callable[[re.Match[str]], str]:
        def replace(match: re.Match[str]) -> str:
            nonlocal hit
            blob = decode(match.group(0))
            if blob is not None and is_private_key_der(blob):
                hit = True
                return REDACTED_VALUE
            return match.group(0)

        return replace

    for pattern, decode in _DER_RUNS:
        text = pattern.sub(replacer(decode), text)
    return text, hit


# ---------------------------------------------------------------------------
# What a KEY looks like, and what an algorithm name looks like
# ---------------------------------------------------------------------------

#: Algorithm, mode, padding, curve and encoding vocabulary. A literal made
#: ENTIRELY of these words (and numbers) is a name -- "PBKDF2WithHmacSHA256",
#: "AES/GCM/NoPadding" -- never key material.
_VOCABULARY = frozenset(
    {
        # ciphers and modes
        "aes",
        "des",
        "desede",
        "tripledes",
        "3des",
        "blowfish",
        "twofish",
        "camellia",
        "aria",
        "sm",
        "rc",
        "idea",
        "cast",
        "chacha",
        "xchacha",
        "salsa",
        "poly",
        "cbc",
        "ecb",
        "gcm",
        "ctr",
        "cfb",
        "ofb",
        "ccm",
        "siv",
        "xts",
        "ocb",
        "wrap",
        "kw",
        "kwp",
        # public key, curves, post-quantum
        "rsa",
        "dsa",
        "ec",
        "ecdsa",
        "ecdh",
        "ecdhe",
        "dh",
        "dhe",
        "eddsa",
        "ed",
        "x",
        "secp",
        "sect",
        "prime",
        "brainpoolp",
        "p",
        "r",
        "k",
        "t",
        "v",
        "curve",
        "mlkem",
        "ml",
        "kem",
        "mldsa",
        "slh",
        "slhdsa",
        "sphincs",
        "falcon",
        "kyber",
        "dilithium",
        "frodo",
        "ntru",
        "hqc",
        # hashes, MACs, KDFs
        "sha",
        "md",
        "hmac",
        "gmac",
        "cmac",
        "kmac",
        "blake",
        "keccak",
        "shake",
        "ripemd",
        "whirlpool",
        "pbkdf",
        "hkdf",
        "scrypt",
        "argon",
        "argon2id",
        "bcrypt",
        "kdf",
        "prng",
        "drbg",
        "sha1prng",
        "native",
        # padding and wrapping grammar
        "pkcs",
        "oaep",
        "pss",
        "mgf",
        "padding",
        "nopadding",
        "no",
        "none",
        "with",
        "and",
        "mode",
        "a",
        # protocols, formats, encodings
        "tls",
        "ssl",
        "dtls",
        "tlsv",
        "sslv",
        "hs",
        "rs",
        "es",
        "ps",
        "jwt",
        "jws",
        "jwe",
        "x509",
        "der",
        "pem",
        "pkix",
        "spki",
        "utf",
        "ascii",
        "iso",
        "latin",
        "base",
        "hex",
    }
)
_WORD = re.compile(r"[A-Z]+[0-9]*(?![a-z])|[A-Z]?[a-z]+[0-9]*|[0-9]+")
_NAME_CHARS = re.compile(r"[A-Za-z0-9/_.:\- ]+")


def _known(token: str) -> bool:
    lower = token.lower()
    return (
        lower in _VOCABULARY
        or lower.isdigit()
        or lower.rstrip("0123456789") in _VOCABULARY
    )


def _is_vocabulary(value: str) -> bool:
    if value.lower() in _VOCABULARY:
        return True
    if not _NAME_CHARS.fullmatch(value):
        return False
    words = _WORD.findall(value)
    return bool(words) and all(_known(word) for word in words)


#: Words joined by `_` or `-`, all one case: a name, a constant, an env var.
_IDENTIFIER_SHAPED = re.compile(
    r"[a-z][a-z0-9]*(?:[_-][a-z0-9]+)+|[A-Z][A-Z0-9]*(?:[_-][A-Z0-9]+)+"
)
_KEY_ALPHABET = re.compile(r"[A-Za-z0-9+/_-]+={0,2}")
_HEX_ONLY = re.compile(r"(?:0[xX])?[0-9A-Fa-f]+")
#: Bits per character. Rejects a repeating filler ("0000...", "abab...") that
#: no key generator produces; ADR-0034's candidate rule makes the same cut.
_MIN_ENTROPY = 3.0
#: ADR-0034: a candidate key is 32 or more hex or base64 characters.
_MIN_NAMED_KEY_CHARS = 32


def _entropy(text: str) -> float:
    total = len(text)
    return -sum(
        (count / total) * math.log2(count / total) for count in Counter(text).values()
    )


def _decodes_to_public_der(value: str) -> bool:
    candidates = [_from_hex(value)] if _HEX_ONLY.fullmatch(value) else []
    candidates.append(_from_base64(value))
    return any(blob is not None and _is_public_der(blob) for blob in candidates)


def _looks_like_key(value: str) -> bool:
    if len(value) < _MIN_NAMED_KEY_CHARS or not _KEY_ALPHABET.fullmatch(value):
        return False
    if _entropy(value) < _MIN_ENTROPY:
        return False
    if _IDENTIFIER_SHAPED.fullmatch(value) or _is_vocabulary(value):
        return False
    return not _decodes_to_public_der(value)


# ---------------------------------------------------------------------------
# Rule 3 -- a secret-named, high-entropy literal
# ---------------------------------------------------------------------------

_QUOTED = re.compile(
    r"""(?P<quote>["'`])(?P<body>(?:\\.|(?!(?P=quote))[^\\\n])*)(?P=quote)"""
)
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_ASSIGNED = re.compile(
    r"(?P<name>[A-Za-z_$][A-Za-z0-9_$.-]*)(?P<sep>\s*[:=]\s*)"
    r"(?P<value>[A-Za-z0-9+/_-]{32,}={0,2})(?![A-Za-z0-9+/_=-])"
)
#: A trailing comment, so a key word in a remark does not make the code on the
#: line a secret context. Only `# ` / `// ` after whitespace: `#define` stays.
_COMMENT = re.compile(r"(?:^|\s)(?:#|//)\s")

_SECRET_WORDS = frozenset(
    {
        "secret",
        "secrets",
        "passphrase",
        "password",
        "passwords",
        "passwd",
        "pwd",
        "credential",
        "credentials",
        "privkey",
        "psk",
        "apikey",
    }
)
_KEY_WORDS = frozenset({"key", "keys"})
#: A word that turns "key" into metadata or a public thing.
_NOT_SECRET = frozenset(
    {
        "public",
        "pub",
        "cert",
        "certs",
        "certificate",
        "certificates",
        "fingerprint",
        "fingerprints",
        "thumbprint",
        "id",
        "ids",
        "name",
        "names",
        "size",
        "sizes",
        "len",
        "length",
        "bits",
        "type",
        "types",
        "alg",
        "algo",
        "algorithm",
        "algorithms",
        "file",
        "files",
        "path",
        "paths",
        "dir",
        "url",
        "uri",
        "usage",
        "usages",
        "pair",
        "generator",
        "factory",
        "store",
        "format",
        "encoding",
        "hash",
        "hashes",
        "digest",
        "checksum",
        "index",
        "idx",
        "count",
        "version",
        "ref",
        "label",
        "header",
        "column",
        "field",
        "prefix",
        "suffix",
        "code",
        "map",
        "cache",
        "event",
        "board",
        "stroke",
        "press",
        "down",
        "up",
    }
)


def _words_of(identifier: str) -> set[str]:
    return {word.lower() for word in _WORD.findall(identifier)}


def _names_a_secret(identifier: str) -> bool:
    words = _words_of(identifier)
    if words & _SECRET_WORDS:
        return True
    return bool(words & _KEY_WORDS) and not words & _NOT_SECRET


def _secret_context(text: str) -> bool:
    code = _QUOTED.sub(" ", text)
    lines = (_COMMENT.split(line, maxsplit=1)[0] for line in code.splitlines())
    return any(
        _names_a_secret(identifier)
        for line in lines
        for identifier in _IDENTIFIER.findall(line)
    )


def _redact_secret_names(text: str) -> tuple[str, bool]:
    if not _secret_context(text):
        return text, False
    hit = False

    def literal(match: re.Match[str]) -> str:
        nonlocal hit
        if not _looks_like_key(match.group("body")):
            return match.group(0)
        hit = True
        quote = match.group("quote")
        return f"{quote}{REDACTED_VALUE}{quote}"

    def assigned(match: re.Match[str]) -> str:
        nonlocal hit
        if not (
            _names_a_secret(match.group("name"))
            and _looks_like_key(match.group("value"))
        ):
            return match.group(0)
        hit = True
        return f"{match.group('name')}{match.group('sep')}{REDACTED_VALUE}"

    text = _QUOTED.sub(literal, text)
    text = _ASSIGNED.sub(assigned, text)
    return text, hit


# ---------------------------------------------------------------------------
# Rule 4 -- key context: a finding its scanner called key material
# ---------------------------------------------------------------------------

#: A key-material finding's literal needs only this many characters: the
#: scanner has already said the line is about a key.
_FLAGGED_MIN_CHARS = 8
_PUBLIC_MATERIAL = frozenset({"public-key", "public key", "public", "certificate"})
_BARE_TOKEN = re.compile(
    r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_=-])"
)
_SHORT_ESCAPES = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){8,}")
_SHORT_ARRAY = re.compile(rf"(?<![\w.]){_ARRAY_ITEM}(?:\s*,\s*{_ARRAY_ITEM}){{7,}}")
_DIGIT = re.compile(r"[0-9]")
_LETTER = re.compile(r"[A-Za-z]")


def is_key_context(asset_type: object, params: Mapping[str, Any]) -> bool:
    """Whether the finding's own scanner said its evidence is key material."""
    if params.get("candidate") in (True, "true", "True"):
        return True
    material = str(params.get("material", "")).lower()
    return asset_type == "key" and material not in _PUBLIC_MATERIAL


def _redact_flagged(text: str) -> tuple[str, bool]:
    hit = False

    def literal(match: re.Match[str]) -> str:
        nonlocal hit
        body = match.group("body")
        if (
            len(body) < _FLAGGED_MIN_CHARS
            or REDACTED_VALUE in body
            or REDACTED in body
            or _is_vocabulary(body)
        ):
            return match.group(0)
        hit = True
        quote = match.group("quote")
        return f"{quote}{REDACTED_VALUE}{quote}"

    def run(_match: re.Match[str]) -> str:
        nonlocal hit
        hit = True
        return REDACTED_VALUE

    def bare(match: re.Match[str]) -> str:
        nonlocal hit
        token = match.group(0)
        if (
            not (_DIGIT.search(token) and _LETTER.search(token))
            or _IDENTIFIER_SHAPED.fullmatch(token)
            or _is_vocabulary(token)
        ):
            return token
        hit = True
        return REDACTED_VALUE

    text = _QUOTED.sub(literal, text)
    text = _SHORT_ESCAPES.sub(run, text)
    text = _SHORT_ARRAY.sub(run, text)
    text = _BARE_TOKEN.sub(bare, text)
    return text, hit


# ---------------------------------------------------------------------------
# The entry points the schema and the normaliser call
# ---------------------------------------------------------------------------


def _report(
    rules: Sequence[str],
    field: str,
    locator: str | None,
    scanner_id: str | None = None,
) -> None:
    """Say that the backstop acted -- and never what it removed."""
    _log.warning(
        EVENT,
        extra={
            "event": EVENT,
            "rule": ",".join(rules),
            "field": field,
            "locator": locator,
            "scanner_id": scanner_id,
        },
    )


def redact_evidence(text: str, *, field: str, locator: str | None = None) -> str:
    """Rules 1-2 on any evidence text; rule 3 as well when it is a snippet."""
    if _ARMOUR.search(text):
        _report([ARMOUR], field, locator)
        return REDACTED
    rules: list[str] = []
    text, der = _redact_der(text)
    if der:
        rules.append(DER)
    if field == "snippet" and text != REDACTED:
        text, named = _redact_secret_names(text)
        if named:
            rules.append(SECRET_NAME)
    if rules:
        _report(rules, field, locator)
    return text


def redact_key_context(
    text: str, *, locator: str | None = None, scanner_id: str | None = None
) -> str:
    """Rule 4, for the snippet of a finding its scanner called key material."""
    redacted, hit = _redact_flagged(text)
    if hit:
        _report([KEY_CONTEXT], "snippet", locator, scanner_id)
    return redacted


def _redact_param(value: Any) -> Any:
    if isinstance(value, str):
        if _ARMOUR.search(value):
            return REDACTED
        redacted, hit = _redact_der(value)
        return redacted if hit else value
    if isinstance(value, list | tuple):
        items = [_redact_param(item) for item in value]
        if all(new is old for new, old in zip(items, value, strict=True)):
            return value
        return type(value)(items)
    return value


def redact_params(params: dict[str, Any]) -> dict[str, Any]:
    """Rules 1-2 on every string param, and every string in a list param.

    Params reach the CBOM as ``ecdat:param:*`` properties, so they are evidence
    too. Only the structural rules: a param named ``public_key_fingerprint`` is
    exactly the metadata rule 3 must not touch. Returns ``params`` itself when
    nothing changed.
    """
    changed: dict[str, Any] = {}
    for name, value in params.items():
        redacted = _redact_param(value)
        if redacted is not value:
            changed[name] = redacted
            _report([ARMOUR if redacted == REDACTED else DER], f"param:{name}", None)
    return {**params, **changed} if changed else params
