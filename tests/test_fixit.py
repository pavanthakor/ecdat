"""Pillar 3's fix half: a diff is only a fix once a re-scan says so (ADR-0015).

The whole design turns on one refusal: **ECDAT does not trust its own
templates.** A template says "replace this line"; the engine copies the target
into a sandbox, applies the template's own diff *as a diff*, re-runs the
producing scanner over the copy, and only calls the fix verified if the
original finding is gone and nothing Critical arrived in its place. A template
that is subtly wrong -- edits the wrong line, edits a comment, trades a weak
hash for a quantum-broken signature -- fails here rather than in someone's
production config.

Three properties are safety-critical, so each is tested twice: once for the
behaviour, and once as a MUTATION -- the guard is disabled and the test asserts
the unsafe outcome appears. A guard that is not load-bearing is not a guard.

* the real target is never written to (`_sandbox_root`);
* a fix that introduces a new Critical is rejected (`_critical_findings`);
* verification is by re-scan, never by trusting the template
  (`_fix_removed_the_finding`).
"""

from __future__ import annotations

import hashlib
import shutil
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest

import cli
from core.identity import finding_identity
from core.scanner import ScanContext, Target
from core.schema import Evidence, Finding, Occurrence
from correlate.fixit import apply as fixit_apply
from correlate.fixit import engine as fixit_engine
from correlate.fixit import patch as fixit_patch
from correlate.fixit.engine import FixResult, propose_fix
from correlate.fixit.template import Precondition
from correlate.fixit.templates import DEFAULT_TEMPLATES
from scanners.config import ConfigScanner
from scanners.source import SourceScanner

KNOWLEDGE_DIR = Path("knowledge")
FIXTURES = Path("testdata/fixit_fixtures")
QUANTUMBANK = Path("testdata/quantumbank")

#: The context QuantumBank is scanned in.
BFSI: dict[str, Any] = {
    "system": "quantumbank",
    "data_class": "pii",
    "sector": "bfsi",
    "exposure": "internet",
}

#: The context in which an introduced RSA-2048 reaches Critical WITHOUT relying
#: on the India DST pack.
#:
#: `pii` would work today -- it scores 98, of which 20 come from DST. But that
#: makes the blast-radius test depend on a roadmap pack whose facts have
#: already been demoted once (ADR-0017) and could be again if the roadmap is
#: revised. A 50-year data lifetime reaches 80 on quantum 40 + mosca 30 +
#: exposure 10, all standards facts, so this test keeps exercising the gate
#: whatever happens to the DST pack.
SOVEREIGN: dict[str, Any] = {**BFSI, "data_class": "Sovereign"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def context(tmp_path: Path) -> ScanContext:
    return ScanContext(
        knowledge_dir=KNOWLEDGE_DIR, scratch_dir=tmp_path / "fixit-scratch"
    )


def target_for(ref: Path | str, **overrides: Any) -> Target:
    kwargs: dict[str, Any] = {"kind": "repo", "ref": str(ref), **BFSI}
    kwargs.update(overrides)
    return Target(**kwargs)


def scan_with(scanner: Any, target: Target, context: ScanContext) -> list[Finding]:
    return list(scanner.scan(target, context))


def only(findings: Sequence[Finding], **match: Any) -> Finding:
    """The single finding matching every field, or a readable failure."""
    hits = [
        f
        for f in findings
        if all(
            (f.params.get(key[7:]) if key.startswith("params_") else getattr(f, key))
            == value
            for key, value in match.items()
        )
    ]
    assert len(hits) == 1, (
        f"expected exactly one finding matching {match}, got {len(hits)}: "
        f"{[(f.algorithm, f.evidence.occurrences[0].locator) for f in hits]}"
    )
    return hits[0]


def tree_hash(root: Path) -> str:
    """A content hash of every path and every byte under ``root``.

    Names as well as bytes: a fix that created a stray file, or renamed one,
    must be as visible as one that edited a line.
    """
    digest = hashlib.blake2b(digest_size=16)
    for path in sorted(root.rglob("*")):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\x00")
        if path.is_file():
            digest.update(path.read_bytes())
        digest.update(b"\x01")
    return digest.hexdigest()


def copy_fixture(source: Path, destination: Path) -> Path:
    shutil.copytree(source, destination)
    return destination


# ---------------------------------------------------------------------------
# Test-local templates. Deliberately WRONG, each in one specific way, so the
# engine's refusals are proved against a real template rather than a stub.
# ---------------------------------------------------------------------------


class _Md5ToRsaTemplate:
    """Trades a weak hash for a quantum-broken signature primitive.

    The plausible-looking bad fix: MD5 really is replaced, the original finding
    really does disappear, and the result is *worse*. Only the new-Critical
    check catches it.
    """

    id: str = "test-md5-to-rsa"
    scanner_to_reverify: str = "source"
    source: str = "test fixture, not a real recommendation"

    def matches(self, finding: Finding) -> bool:
        return finding.algorithm == "MD5"

    def preconditions(self, finding: Finding, target: Target) -> Precondition:
        return Precondition(ok=True, reason="")

    def make_diff(self, finding: Finding, target: Target) -> str:
        site = fixit_engine.site_of(finding, target)
        assert site is not None
        path = Path(target.ref) / site.relative_path
        old = path.read_text(encoding="utf-8")
        lines = old.splitlines()
        lines[site.line - 1] = lines[site.line - 1].replace(
            "hashlib.md5(payload)",
            "rsa.generate_private_key(public_exponent=65537, key_size=2048)",
        )
        return fixit_patch.make_unified_diff(
            site.relative_path, old, "\n".join(lines) + "\n"
        )


class _CommentOnlyTemplate:
    """Produces a real, applicable diff that fixes nothing.

    The template is convinced it worked. Only the re-scan disagrees.
    """

    id: str = "test-comment-only"
    scanner_to_reverify: str = "config"
    source: str = "test fixture, not a real recommendation"

    def matches(self, finding: Finding) -> bool:
        return finding.asset_type == "protocol"

    def preconditions(self, finding: Finding, target: Target) -> Precondition:
        return Precondition(ok=True, reason="")

    def make_diff(self, finding: Finding, target: Target) -> str:
        site = fixit_engine.site_of(finding, target)
        assert site is not None
        path = Path(target.ref) / site.relative_path
        old = path.read_text(encoding="utf-8")
        return fixit_patch.make_unified_diff(
            site.relative_path, old, "# hardened\n" + old
        )


class _CorruptDiffTemplate:
    """Emits a syntactically valid diff whose context matches nothing."""

    id: str = "test-corrupt-diff"
    scanner_to_reverify: str = "config"
    source: str = "test fixture, not a real recommendation"

    def matches(self, finding: Finding) -> bool:
        return finding.asset_type == "protocol"

    def preconditions(self, finding: Finding, target: Target) -> Precondition:
        return Precondition(ok=True, reason="")

    def make_diff(self, finding: Finding, target: Target) -> str:
        site = fixit_engine.site_of(finding, target)
        assert site is not None
        return (
            f"--- a/{site.relative_path}\n+++ b/{site.relative_path}\n"
            "@@ -1,1 +1,1 @@\n-this line is not in the file\n+replacement\n"
        )


# ---------------------------------------------------------------------------
# The four shipped templates, each verified by a re-scan of a sandbox copy
# ---------------------------------------------------------------------------


def test_nginx_weak_protocol_is_fixed_and_the_fix_is_verified_by_rescan(
    context: ScanContext,
) -> None:
    """TLSv1/1.1/1.2 -> TLSv1.3, confirmed by re-parsing the patched copy."""
    target = target_for(FIXTURES / "nginx_weak")
    finding = only(
        scan_with(ConfigScanner(), target, context),
        asset_type="protocol",
        params_versions="TLSv1,TLSv1.1,TLSv1.2",
    )

    result = propose_fix(finding, target, context=context)

    assert result.applicable is True
    assert result.template_id == "nginx-weak-protocol"
    assert result.verified is True, result.reason
    assert result.diff is not None
    assert "-        ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;" in result.diff
    assert "+        ssl_protocols       TLSv1.3;" in result.diff
    # The diff is PR-ready: git-style a/ and b/ paths, no absolute paths.
    assert "--- a/nginx.conf" in result.diff
    assert "+++ b/nginx.conf" in result.diff
    assert str(target.ref) not in result.diff


def test_quantumbank_legacy_endpoint_gets_a_verified_hybrid_group_fix(
    context: ScanContext,
) -> None:
    """The demo closer: detect -> recommend -> FIX -> re-scan clean.

    legacy.quantumbank.invalid:8443 declares the classical group prime256v1 at
    nginx.conf:22. payments:443 is deliberately NOT the subject: it already
    declares X25519MLKEM768, so its drift is a shipped-library problem, not a
    config one, and this template correctly declines it (asserted below).
    """
    target = target_for(QUANTUMBANK)
    before_hash = tree_hash(Path(target.ref))

    findings = scan_with(ConfigScanner(), target, context)
    classical = only(
        findings,
        primitive="key-agreement",
        algorithm="prime256v1",
        params_endpoint="legacy.quantumbank.invalid:8443",
    )
    assert classical.evidence.occurrences[0].locator.endswith("deploy/nginx.conf:22")

    result = propose_fix(classical, target, context=context)

    assert result.applicable is True
    assert result.template_id == "nginx-add-hybrid-group"
    assert result.verified is True, result.reason
    assert result.diff is not None
    assert "-        ssl_ecdh_curve      prime256v1;" in result.diff
    assert "+        ssl_ecdh_curve      X25519MLKEM768;" in result.diff
    assert "--- a/deploy/nginx.conf" in result.diff
    assert "re-scanned clean" in result.reason
    # Nothing Critical arrived with the fix.
    assert result.new_criticals == ()
    # And the committed fixture is untouched.
    assert tree_hash(Path(target.ref)) == before_hash


def test_the_payments_endpoint_is_already_hybrid_so_no_template_fires(
    context: ScanContext,
) -> None:
    """The honest half of the demo: ECDAT says the nginx config is already right.

    Its drift (declared PQC, observed classical) is the shipped OpenSSL 3.0.2,
    which no config template can fix. Reporting "fixed" here would be a lie.
    """
    target = target_for(QUANTUMBANK)
    hybrid = only(
        scan_with(ConfigScanner(), target, context),
        primitive="key-agreement",
        algorithm="X25519MLKEM768",
        params_endpoint="payments.quantumbank.invalid:443",
    )

    result = propose_fix(hybrid, target, context=context)

    assert result.applicable is False
    assert result.verified is False
    assert result.diff is None


def test_openssl_cnf_classical_groups_get_a_verified_hybrid_fix(
    context: ScanContext,
) -> None:
    target = target_for(FIXTURES / "openssl_legacy")
    groups = only(
        scan_with(ConfigScanner(), target, context),
        primitive="key-agreement",
        algorithm="prime256v1",
    )

    result = propose_fix(groups, target, context=context)

    assert result.applicable is True
    assert result.template_id == "openssl-cnf-groups"
    assert result.verified is True, result.reason
    assert result.diff is not None
    assert "+Groups = X25519MLKEM768:prime256v1:x25519" in result.diff


def test_openssl_cnf_minprotocol_is_raised_and_verified(
    context: ScanContext,
) -> None:
    target = target_for(FIXTURES / "openssl_legacy")
    protocol = only(
        scan_with(ConfigScanner(), target, context),
        asset_type="protocol",
        params_min_version="TLSv1",
    )

    result = propose_fix(protocol, target, context=context)

    assert result.applicable is True
    assert result.template_id == "openssl-cnf-groups"
    assert result.verified is True, result.reason
    assert result.diff is not None
    assert "-MinProtocol = TLSv1" in result.diff
    assert "+MinProtocol = TLSv1.2" in result.diff


def test_md5_used_for_integrity_becomes_sha256_and_is_verified(
    context: ScanContext,
) -> None:
    target = target_for(FIXTURES / "md5_integrity")
    md5 = only(scan_with(SourceScanner(), target, context), algorithm="MD5")

    result = propose_fix(md5, target, context=context)

    assert result.applicable is True
    assert result.template_id == "md5-to-sha256"
    assert result.verified is True, result.reason
    assert result.diff is not None
    assert "-    digest = hashlib.md5(payload)" in result.diff
    assert "+    digest = hashlib.sha256(payload)" in result.diff
    # SHA-256 is a control, not a Critical -- the swap introduced nothing bad.
    assert result.new_criticals == ()


# ---------------------------------------------------------------------------
# The no-guess cases: usage decides the fix, and an unclear usage decides
# nothing at all
# ---------------------------------------------------------------------------


def test_md5_in_a_password_context_is_refused_with_a_reason(
    context: ScanContext,
) -> None:
    """MD5 -> SHA-256 over a password is a faster wrong answer, not a fix."""
    target = target_for(FIXTURES / "md5_password")
    md5 = only(scan_with(SourceScanner(), target, context), algorithm="MD5")

    result = propose_fix(md5, target, context=context)

    assert result.applicable is False
    assert result.verified is False
    assert result.diff is None
    # The template matched -- it is the PRECONDITION that refused, and the
    # reason has to say which usage it saw and what the right fix would be.
    assert result.template_id == "md5-to-sha256"
    assert "password" in result.reason.lower()
    assert any(
        kdf in result.reason.lower() for kdf in ("argon2", "scrypt", "pbkdf2")
    ), result.reason


def test_md5_with_an_undeterminable_usage_is_refused_rather_than_guessed(
    context: ScanContext,
) -> None:
    target = target_for(FIXTURES / "md5_ambiguous")
    md5 = only(scan_with(SourceScanner(), target, context), algorithm="MD5")

    result = propose_fix(md5, target, context=context)

    assert result.applicable is False
    assert result.diff is None
    assert result.template_id == "md5-to-sha256"
    assert "usage" in result.reason.lower()


def test_a_finding_no_template_matches_is_reported_not_crashed(
    context: ScanContext,
) -> None:
    """NO MATCH is an answer, not an exception."""
    target = target_for(QUANTUMBANK)
    sshd = only(
        scan_with(ConfigScanner(), target, context),
        algorithm="SSH-KEX",
    )

    result = propose_fix(sshd, target, context=context)

    assert result.applicable is False
    assert result.verified is False
    assert result.template_id is None
    assert result.diff is None
    assert result.reason


def test_a_hand_built_finding_from_an_unknown_scanner_does_not_crash() -> None:
    """Nothing about propose_fix may assume the finding came from a real scan."""
    finding = Finding(
        scanner_id="binary.elf",
        view="shipped",
        asset_type="algorithm",
        primitive="pke",
        algorithm="RSA",
        evidence=Evidence(
            occurrences=[
                Occurrence(view="shipped", locator="sha256:ab/lib.so", detail="symbol")
            ]
        ),
    )
    result = propose_fix(finding, target_for(QUANTUMBANK))
    assert result == FixResult(
        applicable=False,
        verified=False,
        template_id=None,
        diff=None,
        reason=result.reason,
        new_findings=(),
        new_criticals=(),
    )


# ---------------------------------------------------------------------------
# SAFETY: the verification loop's three refusals
# ---------------------------------------------------------------------------


def test_a_fix_that_introduces_a_new_critical_is_rejected(
    context: ScanContext,
) -> None:
    """The MD5 really is gone -- and the fix is still refused.

    A template that trades a broken hash for RSA-2048 has removed the original
    finding, so a verifier that only checked "is it gone?" would call this a
    success. The blast radius is what makes it a failure.
    """
    target = target_for(FIXTURES / "md5_integrity", **SOVEREIGN)
    md5 = only(scan_with(SourceScanner(), target, context), algorithm="MD5")

    result = propose_fix(md5, target, context=context, templates=[_Md5ToRsaTemplate()])

    assert result.applicable is True
    assert result.template_id == "test-md5-to-rsa"
    assert result.verified is False
    # The reason must NAME the new Critical, not merely report a rejection.
    assert "Critical" in result.reason
    assert "RSA" in result.reason
    assert result.new_criticals != ()
    assert any("RSA" in entry for entry in result.new_criticals)


def test_a_template_whose_diff_does_not_remove_the_finding_is_rejected(
    context: ScanContext,
) -> None:
    """The diff applies cleanly, changes a comment, and fixes nothing."""
    target = target_for(FIXTURES / "nginx_weak")
    protocol = only(scan_with(ConfigScanner(), target, context), asset_type="protocol")

    result = propose_fix(
        protocol, target, context=context, templates=[_CommentOnlyTemplate()]
    )

    assert result.applicable is True
    assert result.verified is False
    assert "still present" in result.reason.lower()


def test_the_real_target_is_byte_identical_after_propose_fix(
    tmp_path: Path, context: ScanContext
) -> None:
    """READ-ONLY: hash the whole tree, propose every fix, hash it again."""
    root = copy_fixture(QUANTUMBANK, tmp_path / "estate")
    target = target_for(root)
    before = tree_hash(root)

    findings = scan_with(ConfigScanner(), target, context)
    assert findings, "the read-only proof is worthless if nothing was proposed"
    results = [propose_fix(f, target, context=context) for f in findings]

    assert tree_hash(root) == before
    # And the proof is only meaningful if at least one fix really ran the loop.
    assert any(r.verified for r in results)


def test_a_diff_that_does_not_apply_cleanly_is_not_verified(
    context: ScanContext,
) -> None:
    """A template whose diff lies about the file fails verification.

    The context lines do not match, so the patch is refused in the sandbox and
    the fix never reaches a human -- which is the only place a bad diff can
    still be caught for free.
    """
    target = target_for(FIXTURES / "nginx_weak")
    protocol = only(scan_with(ConfigScanner(), target, context), asset_type="protocol")

    result = propose_fix(
        protocol, target, context=context, templates=[_CorruptDiffTemplate()]
    )

    assert result.applicable is True
    assert result.verified is False
    assert result.diff is None
    assert "apply" in result.reason.lower()


def test_a_diff_that_escapes_the_sandbox_root_is_refused(tmp_path: Path) -> None:
    """Path traversal in a diff header is a patch that never runs."""
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("original\n", encoding="utf-8")

    escaping = (
        "--- a/../outside.txt\n+++ b/../outside.txt\n"
        "@@ -1,1 +1,1 @@\n-original\n+owned\n"
    )

    with pytest.raises(fixit_patch.PatchError):
        fixit_patch.apply_unified_diff(sandbox, escaping)

    assert outside.read_text(encoding="utf-8") == "original\n"


def test_the_same_finding_and_target_produce_an_identical_diff(
    context: ScanContext,
) -> None:
    """DETERMINISM: no timestamps, no temp paths, no dict ordering."""
    target = target_for(QUANTUMBANK)
    classical = only(
        scan_with(ConfigScanner(), target, context),
        primitive="key-agreement",
        algorithm="prime256v1",
    )

    first = propose_fix(classical, target, context=context)
    second = propose_fix(classical, target, context=context)

    assert first.diff == second.diff
    assert first == second


# ---------------------------------------------------------------------------
# MUTATION-STYLE NEGATIVES
#
# Each disables exactly one guard and asserts the unsafe outcome appears. If a
# future edit makes a guard decorative, the matching test here goes green in
# the wrong direction and the paired behaviour test above goes red.
# ---------------------------------------------------------------------------


def test_mutation_removing_the_new_critical_check_accepts_the_bad_fix(
    context: ScanContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Disable the blast-radius check and the RSA-2048 swap sails through."""
    target = target_for(FIXTURES / "md5_integrity", **SOVEREIGN)
    md5 = only(scan_with(SourceScanner(), target, context), algorithm="MD5")

    def no_blast_radius_check(*_: object, **__: object) -> list[str]:
        return []

    monkeypatch.setattr(fixit_engine, "_critical_findings", no_blast_radius_check)
    mutated = propose_fix(md5, target, context=context, templates=[_Md5ToRsaTemplate()])

    assert mutated.verified is True, (
        "the new-Critical check is the ONLY thing rejecting this fix; if this "
        "assertion fails the guard has moved and the paired test must move too"
    )


def test_mutation_pointing_the_sandbox_at_the_real_target_modifies_it(
    tmp_path: Path, context: ScanContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Disable the copy and the engine edits the real tree.

    Run against a throwaway copy, precisely because the mutation makes the
    engine do the thing every other test asserts it never does.
    """
    root = copy_fixture(FIXTURES / "nginx_weak", tmp_path / "estate")
    target = target_for(root)
    before = tree_hash(root)
    protocol = only(scan_with(ConfigScanner(), target, context), asset_type="protocol")

    def no_sandbox(real_root: Path, _sandbox: Path) -> Path:
        return real_root

    monkeypatch.setattr(fixit_engine, "_sandbox_root", no_sandbox)
    propose_fix(protocol, target, context=context)

    assert tree_hash(root) != before, (
        "the sandbox copy is the ONLY thing keeping the real target read-only"
    )


def test_mutation_trusting_the_template_accepts_an_ineffective_fix(
    context: ScanContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Skip the re-scan check and a comment-only 'fix' is called verified."""
    target = target_for(FIXTURES / "nginx_weak")
    protocol = only(scan_with(ConfigScanner(), target, context), asset_type="protocol")

    def trust_the_template(*_: object, **__: object) -> bool:
        return True

    monkeypatch.setattr(fixit_engine, "_fix_removed_the_finding", trust_the_template)
    mutated = propose_fix(
        protocol, target, context=context, templates=[_CommentOnlyTemplate()]
    )

    assert mutated.verified is True, (
        "the re-scan is the ONLY thing rejecting a template that fixes nothing"
    )


# ---------------------------------------------------------------------------
# The CBOM post-pass
# ---------------------------------------------------------------------------


def scored_cbom(target: Target, findings: Sequence[Finding]) -> str:
    from core.normalise import normalise
    from policy.apply import ScoreInputs, apply_policy
    from policy.engine import default_packs

    _, cbom_json = normalise(findings, target)
    return apply_policy(
        cbom_json,
        default_packs(),
        inputs=ScoreInputs(
            data_class=target.data_class,
            sector=target.sector,
            exposure=target.exposure,
            knowledge_dir=KNOWLEDGE_DIR,
        ),
    )


def properties_of(document: dict[str, Any], bom_ref: str) -> list[tuple[str, str]]:
    for component in document["components"]:
        if component["bom-ref"] == bom_ref:
            return [(p["name"], p["value"]) for p in component.get("properties", [])]
    raise AssertionError(f"no component with bom-ref {bom_ref}")


def test_a_verified_fix_lands_on_its_own_component_as_ecdat_fix_properties(
    context: ScanContext,
) -> None:
    import json

    target = target_for(FIXTURES / "nginx_weak")
    findings = scan_with(ConfigScanner(), target, context)
    protocol = only(findings, asset_type="protocol")

    fixes = fixit_apply.propose_fixes(findings, target, context=context)
    document = json.loads(fixit_apply.apply_fixes(scored_cbom(target, findings), fixes))

    names = dict(properties_of(document, finding_identity(protocol, target)))
    assert names["ecdat:fix:template"] == "nginx-weak-protocol"
    assert names["ecdat:fix:verified"] == "true"
    assert "ssl_protocols       TLSv1.3;" in names["ecdat:fix:diff"]
    assert names["ecdat:fix:source"]


def test_an_unverified_fix_never_carries_a_diff_property(
    context: ScanContext,
) -> None:
    """The invariant a dashboard can rely on: a diff on a component IS verified.

    An unverified diff shown next to a fix button is how an unproven patch
    reaches production.
    """
    import json

    target = target_for(FIXTURES / "md5_password")
    findings = scan_with(SourceScanner(), target, context)

    fixes = fixit_apply.propose_fixes(findings, target, context=context)
    document = json.loads(fixit_apply.apply_fixes(scored_cbom(target, findings), fixes))

    for component in document["components"]:
        names = {p["name"]: p["value"] for p in component.get("properties", [])}
        if "ecdat:fix:diff" in names:
            assert names.get("ecdat:fix:verified") == "true"
    # The refusal itself is recorded, so the dashboard can explain it.
    md5 = only(findings, algorithm="MD5")
    names = dict(properties_of(document, finding_identity(md5, target)))
    assert names["ecdat:fix:verified"] == "false"
    assert "ecdat:fix:diff" not in names
    assert "password" in names["ecdat:fix:reason"].lower()


def test_applying_the_fix_pass_twice_is_a_no_op(context: ScanContext) -> None:
    target = target_for(FIXTURES / "nginx_weak")
    findings = scan_with(ConfigScanner(), target, context)
    fixes = fixit_apply.propose_fixes(findings, target, context=context)

    once = fixit_apply.apply_fixes(scored_cbom(target, findings), fixes)
    twice = fixit_apply.apply_fixes(once, fixes)

    assert once == twice


# ---------------------------------------------------------------------------
# The CLI
# ---------------------------------------------------------------------------


def test_ecdat_fix_prints_verified_diffs_and_never_writes_to_the_target(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.orchestrator import run_scan

    monkeypatch.setenv("ECDAT_SCRATCH_DIR", str(tmp_path / "scratch"))
    root = copy_fixture(FIXTURES / "nginx_weak", tmp_path / "estate")
    target = target_for(root)
    scan_id = run_scan(
        target, [ConfigScanner()], ScanContext(KNOWLEDGE_DIR, tmp_path / "scratch")
    )
    before = tree_hash(root)
    capsys.readouterr()

    exit_code = cli.main(
        [
            "fix",
            scan_id,
            "--scanner",
            "config",
            "--sector",
            "bfsi",
            "--exposure",
            "internet",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "nginx-weak-protocol" in captured.out
    assert "verified: re-scanned clean" in captured.out
    assert "ssl_protocols       TLSv1.3;" in captured.out
    assert tree_hash(root) == before


def test_ecdat_fix_saves_patches_without_touching_the_target(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.orchestrator import run_scan

    monkeypatch.setenv("ECDAT_SCRATCH_DIR", str(tmp_path / "scratch"))
    root = copy_fixture(FIXTURES / "openssl_legacy", tmp_path / "estate")
    target = target_for(root)
    scan_id = run_scan(
        target, [ConfigScanner()], ScanContext(KNOWLEDGE_DIR, tmp_path / "scratch")
    )
    before = tree_hash(root)
    out_dir = tmp_path / "patches"

    exit_code = cli.main(["fix", scan_id, "--scanner", "config", "--out", str(out_dir)])
    capsys.readouterr()

    assert exit_code == 0
    patches = sorted(out_dir.glob("*.patch"))
    assert patches, "a verified fix must be saved when --out is given"
    assert all("--- a/openssl.cnf" in p.read_text(encoding="utf-8") for p in patches)
    assert tree_hash(root) == before


def test_ecdat_fix_says_why_a_fix_was_not_verified(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refusal is output, not silence."""
    from core.orchestrator import run_scan

    monkeypatch.setenv("ECDAT_SCRATCH_DIR", str(tmp_path / "scratch"))
    root = copy_fixture(FIXTURES / "md5_password", tmp_path / "estate")
    target = target_for(root)
    scan_id = run_scan(
        target, [SourceScanner()], ScanContext(KNOWLEDGE_DIR, tmp_path / "scratch")
    )

    exit_code = cli.main(["fix", scan_id, "--scanner", "source"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "not applicable" in captured.out.lower()
    assert "password" in captured.out.lower()


def test_ecdat_fix_on_an_unknown_scan_id_fails_cleanly(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["fix", "no-such-scan"]) == 2
    assert "no-such-scan" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# The template contract itself
# ---------------------------------------------------------------------------


def test_every_shipped_template_names_a_registered_scanner() -> None:
    """A template whose verifier does not exist cannot be verified by re-scan.

    This is the rule that kept dockerfile-base-bump and dep-bump out of the
    shipped set: nothing reads a Dockerfile or a dependency manifest yet.
    """
    from core import registry

    available = set(registry.available_ids())
    for template in DEFAULT_TEMPLATES:
        assert template.scanner_to_reverify in available, template.id


def test_every_shipped_template_cites_a_source() -> None:
    """No uncited crypto facts -- CLAUDE.md applies to fixes too."""
    for template in DEFAULT_TEMPLATES:
        assert template.source.strip(), template.id


def test_shipped_template_ids_are_unique_and_stable() -> None:
    ids = [t.id for t in DEFAULT_TEMPLATES]
    assert ids == sorted(set(ids))
    assert set(ids) == {
        "md5-to-sha256",
        "nginx-add-hybrid-group",
        "nginx-weak-protocol",
        "openssl-cnf-groups",
    }


def test_propose_fix_never_opens_the_target_for_writing(
    context: ScanContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A direct guard on the code path, not just on the resulting bytes.

    The tree hash proves nothing changed; this proves nothing even TRIED,
    which is the property that survives a fix that happens to write identical
    bytes.
    """
    target = target_for(QUANTUMBANK)
    real_root = Path(target.ref).resolve()
    classical = only(
        scan_with(ConfigScanner(), target, context),
        primitive="key-agreement",
        algorithm="prime256v1",
    )

    opened_for_writing: list[str] = []
    real_open = Path.open

    def guarded(self: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if set(mode) & set("wax+"):
            resolved = self.resolve()
            if resolved == real_root or real_root in resolved.parents:
                opened_for_writing.append(str(resolved))
        return real_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded)
    result = propose_fix(classical, target, context=context)

    assert result.verified is True, result.reason
    assert opened_for_writing == []


@pytest.fixture(autouse=True)
def _isolated_scratch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    """Keep every scanner's scratch output out of the repository."""
    monkeypatch.setenv("ECDAT_SCRATCH_DIR", str(tmp_path / "scratch"))
    yield
