"""The config scanner: the endpoint-oriented declared view (ADR-0013).

ADR-0012 made config-declared vs observed the primary drift axis and then had
to admit nothing produced the config side. This is that producer, and it is
what makes R2/R3/R4 run against a real parser rather than hand-built
components.

The characteristic failure of a config parser is not missing a directive -- it
is attributing one to the wrong block. `ssl_ecdh_curve` inside `server { listen
443; }` is a fact about that endpoint and about no other, and getting it wrong
would silently ruin the correlator's join while every test still passed. So the
endpoint is part of the answer key, and two server blocks with different crypto
are the central fixture.

Precision matters more than recall here for the same reason it did for the
source scanner: a commented-out directive reported as live configuration is a
finding an operator will chase and find nothing behind.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
import yaml

from core import registry
from core.scanner import ScanContext, Scanner, Target
from core.schema import Finding
from scanners.config import ConfigScanner

FIXTURES = Path("testdata/config_fixtures")
ANSWERS: dict[str, Any] = yaml.safe_load(
    (FIXTURES / "answer_key.yaml").read_text(encoding="utf-8")
)
EXPECTED: dict[str, list[dict[str, Any]]] = ANSWERS["expected"]
SYSTEM = "quantumbank"


@pytest.fixture(scope="module")
def context(tmp_path_factory: pytest.TempPathFactory) -> ScanContext:
    return ScanContext(
        knowledge_dir=Path("knowledge"),
        scratch_dir=tmp_path_factory.mktemp("config-scratch"),
    )


@pytest.fixture(scope="module")
def findings(context: ScanContext) -> list[Finding]:
    target = Target(kind="repo", ref=str(FIXTURES), system=SYSTEM)
    return list(ConfigScanner().scan(target, context))


def endpoint_of(finding: Finding) -> str:
    return str(finding.params.get("endpoint", ""))


def file_of(finding: Finding) -> str:
    locator = finding.evidence.occurrences[0].locator
    path = locator.rpartition(":")[0]
    return str(Path(path).resolve().relative_to(FIXTURES.resolve()))


def at(findings: list[Finding], **match: Any) -> list[Finding]:
    out = []
    for f in findings:
        if all(
            getattr(f, k, None) == v or f.params.get(k) == v for k, v in match.items()
        ):
            out.append(f)
    return out


# --------------------------------------------------------------------------
# Plugin contract
# --------------------------------------------------------------------------


def test_satisfies_the_scanner_protocol() -> None:
    assert isinstance(ConfigScanner(), Scanner)


def test_identity_and_view() -> None:
    scanner = ConfigScanner()
    assert scanner.id == "config"
    assert scanner.view == "declared"


@pytest.mark.parametrize("kind", ["repo", "directory"])
def test_supports_source_trees(kind: str) -> None:
    assert ConfigScanner().supports(Target(kind=kind, ref="."))  # type: ignore[arg-type]


@pytest.mark.parametrize("kind", ["image", "host", "endpoint", "spool"])
def test_declines_other_target_kinds(kind: str) -> None:
    assert not ConfigScanner().supports(Target(kind=kind, ref="x"))  # type: ignore[arg-type]


def test_registered_in_the_registry() -> None:
    assert registry.available_ids() == [
        "config",
        "container",
        "deps",
        "runtime-spool",
        "source",
    ]
    (scanner,) = registry.get_scanners(["config"])
    assert isinstance(scanner, ConfigScanner)


# --------------------------------------------------------------------------
# nginx: the endpoint IS the join key
# --------------------------------------------------------------------------


def test_the_hybrid_group_is_found_with_its_endpoint(
    findings: list[Finding],
) -> None:
    (group,) = at(
        findings, algorithm="X25519MLKEM768", endpoint="api.quantumbank.invalid:443"
    )

    assert group.view == "declared"
    assert group.asset_type == "algorithm"
    assert group.primitive == "key-agreement"
    assert group.params["group"] == "X25519MLKEM768"
    assert group.params["hybrid"] is True
    # The endpoint, NOT the file path -- this is what the correlator joins on.
    assert group.params["endpoint"] == "api.quantumbank.invalid:443"


def test_weak_protocols_are_found_on_the_other_endpoint(
    findings: list[Finding],
) -> None:
    (protocol,) = at(
        findings, asset_type="protocol", endpoint="legacy.quantumbank.invalid:8443"
    )

    assert protocol.algorithm == "TLS"
    assert protocol.params["min_version"] == "TLSv1"
    assert "TLSv1.1" in protocol.params["versions"]


def test_two_server_blocks_produce_two_endpoints(
    findings: list[Finding],
) -> None:
    """The characteristic failure this fixture exists to catch.

    A parser that attributes directives to the file rather than the block would
    put X25519MLKEM768 and TLSv1 on the same endpoint, and the correlator would
    then compare a handshake against whichever config it happened to pick.
    """
    nginx = [f for f in findings if file_of(f) == "nginx/nginx.conf"]
    endpoints = {endpoint_of(f) for f in nginx}

    assert endpoints == {
        "api.quantumbank.invalid:443",
        "legacy.quantumbank.invalid:8443",
    }


def test_directives_do_not_leak_between_blocks(findings: list[Finding]) -> None:
    """The hybrid group belongs to :443 and to nothing else."""
    hybrids = at(findings, algorithm="X25519MLKEM768")
    nginx_hybrids = [f for f in hybrids if file_of(f) == "nginx/nginx.conf"]

    assert len(nginx_hybrids) == 1
    assert endpoint_of(nginx_hybrids[0]) == "api.quantumbank.invalid:443"

    legacy = [f for f in findings if endpoint_of(f).endswith(":8443")]
    assert all(f.algorithm != "X25519MLKEM768" for f in legacy)


def test_the_declared_cipher_list_reaches_the_protocol_finding(
    findings: list[Finding],
) -> None:
    """R4 reads `cipher_suites` off the declared protocol component."""
    (protocol,) = at(
        findings, asset_type="protocol", endpoint="api.quantumbank.invalid:443"
    )

    suites = protocol.params["cipher_suites"]
    assert "TLS_AES_256_GCM_SHA384" in suites
    assert "," in suites, "nginx's ':' separators must become the CBOM's ','"


def test_a_declared_certificate_is_recorded(findings: list[Finding]) -> None:
    certificates = at(findings, asset_type="certificate")
    assert certificates
    assert any("api.pem" in str(c.params.get("path", "")) for c in certificates)


def test_config_findings_are_configurable(findings: list[Finding]) -> None:
    """Config is by definition changeable without a code edit; this feeds the
    migration-effort estimate."""
    assert findings
    assert all(f.configurable is True for f in findings)


# --------------------------------------------------------------------------
# Global-scope formats
# --------------------------------------------------------------------------


def test_sshd_kex_is_found_with_a_system_scope(findings: list[Finding]) -> None:
    (kex,) = at(findings, algorithm="SSH-KEX")

    assert kex.params["endpoint"] == f"sshd@{SYSTEM}"
    assert kex.primitive == "key-agreement"
    assert "diffie-hellman-group1-sha1" in kex.params["algorithms"]


def test_sshd_reports_ciphers_macs_and_host_keys(findings: list[Finding]) -> None:
    for algorithm in ("SSH-CIPHERS", "SSH-MACS", "SSH-HOSTKEY"):
        assert at(findings, algorithm=algorithm), algorithm


def test_openssl_cnf_groups_and_min_protocol(findings: list[Finding]) -> None:
    (group,) = at(findings, algorithm="X25519MLKEM768", endpoint=f"openssl@{SYSTEM}")
    assert group.params["hybrid"] is True

    (protocol,) = at(findings, asset_type="protocol", endpoint=f"openssl@{SYSTEM}")
    assert protocol.params["min_version"] == "TLSv1.2"


def test_a_global_scope_marker_is_not_mistaken_for_an_endpoint() -> None:
    from scanners.config import global_scope

    assert global_scope("sshd", "quantumbank") == "sshd@quantumbank"
    assert ":" not in global_scope("openssl", "quantumbank")


# --------------------------------------------------------------------------
# Precision: the decoys
# --------------------------------------------------------------------------


def test_the_decoy_file_produces_nothing(findings: list[Finding]) -> None:
    """A commented-out directive reported as live config is a finding an
    operator will chase and find nothing behind."""
    false_positives = [
        (f.algorithm, endpoint_of(f))
        for f in findings
        if file_of(f) in ANSWERS["must_not_fire"]
    ]
    assert false_positives == []


def test_commented_directives_are_ignored(findings: list[Finding]) -> None:
    """`#ssl_ecdh_curve X25519MLKEM768;` in the decoys must not become a group."""
    hybrids = at(findings, algorithm="X25519MLKEM768")
    assert all(file_of(f) != "nginx/conf.d/decoys.conf" for f in hybrids)


def test_a_server_block_without_tls_produces_nothing(
    findings: list[Finding],
) -> None:
    assert not [f for f in findings if endpoint_of(f).endswith(":80")]


# --------------------------------------------------------------------------
# Canonicalisation: declared must compare EQUAL to observed
# --------------------------------------------------------------------------


def test_a_declared_group_equals_the_observed_spelling(
    findings: list[Finding],
) -> None:
    """The whole join depends on this. ADR-0011's observed side reads
    `SSL_group_to_name`, which returns exactly `X25519MLKEM768`."""
    from agent.to_finding import event_to_findings

    (declared,) = at(
        findings, algorithm="X25519MLKEM768", endpoint="api.quantumbank.invalid:443"
    )
    observed = [
        f
        for f in event_to_findings(
            {
                "comm": "nginx",
                "pid": 1,
                "tid": 1,
                "phase": "return",
                "retval": 1,
                "probe": "SSL_do_handshake",
                "observed_version": "TLSv1.3",
                "observed_cipher": "TLS_AES_256_GCM_SHA384",
                "observed_group": "X25519MLKEM768",
            }
        )
        if f.primitive == "key-agreement"
    ]

    assert declared.algorithm == observed[0].algorithm
    assert declared.params["group"] == observed[0].params["group"]
    assert declared.params["hybrid"] == observed[0].params["hybrid"] is True


def test_determinism(context: ScanContext, findings: list[Finding]) -> None:
    target = Target(kind="repo", ref=str(FIXTURES), system=SYSTEM)
    again = list(ConfigScanner().scan(target, context))
    assert [f.model_dump() for f in again] == [f.model_dump() for f in findings]


# --------------------------------------------------------------------------
# THE HEADLINE: drift now runs against a PARSED declared side
# --------------------------------------------------------------------------


def _cbom_from(declared: list[Finding], extra: list[dict[str, Any]]) -> str:
    from core.normalise import normalise

    target = Target(kind="repo", ref=str(FIXTURES), system=SYSTEM)
    _bom, cbom_json = normalise(declared, target)
    document = json.loads(cbom_json)
    document.setdefault("metadata", {})["component"] = {
        "name": SYSTEM,
        "type": "application",
    }
    document["components"].extend(extra)
    return json.dumps(document)


def _drifts(scored: str) -> list[dict[str, list[str]]]:
    out = []
    for component in json.loads(scored)["components"]:
        collected: dict[str, list[str]] = {}
        for prop in component["properties"]:
            collected.setdefault(prop["name"], []).append(prop["value"])
        if "ecdat:drift:kind" in collected:
            out.append(collected)
    return out


def test_r1_fires_against_a_parsed_declared_side(findings: list[Finding]) -> None:
    """R1 with no hand-built declared component: the config parser supplies it."""
    from correlate.apply import apply_drift
    from tests.test_correlator import shipped_openssl

    declared = at(
        findings, algorithm="X25519MLKEM768", endpoint="api.quantumbank.invalid:443"
    )
    scored = apply_drift(_cbom_from(declared, [shipped_openssl("3.0.2", "False")]))

    drifted = _drifts(scored)
    assert drifted, "R1 did not fire against the parsed config"
    (entry,) = drifted
    assert entry["ecdat:drift:kind"] == ["shipped-cannot-do-declared"]
    assert entry["ecdat:drift:declared"] == ["X25519MLKEM768"]
    assert "ML-KEM" in entry["ecdat:drift:cause"][0]
    assert entry["ecdat:band"][0] in ("High", "Critical")
    # The declared side is cited at its real config line.
    assert any("nginx.conf" in e for e in entry["ecdat:drift:evidence"])


def test_r2_fires_end_to_end_on_a_shared_endpoint(
    findings: list[Finding],
) -> None:
    """Config declares hybrid on an endpoint; a handshake there went classical."""
    from correlate.apply import apply_drift
    from tests.test_correlator import component

    declared = at(
        findings, algorithm="X25519MLKEM768", endpoint="api.quantumbank.invalid:443"
    )
    observed = component(
        "x25519",
        "observed",
        primitive="key-agreement",
        params={"group": "x25519", "enrichment": "full"},
        locator="host:api-07:pid2231",
    )
    scored = apply_drift(_cbom_from(declared, [observed]))

    kinds = {k for d in _drifts(scored) for k in d["ecdat:drift:kind"]}
    assert "declared-pqc-observed-classical" in kinds


def test_a_partial_observation_stays_the_weaker_signal_end_to_end(
    findings: list[Finding],
) -> None:
    from correlate.apply import apply_drift
    from tests.test_correlator import component

    declared = at(
        findings, algorithm="X25519MLKEM768", endpoint="api.quantumbank.invalid:443"
    )
    partial = component(
        "TLS",
        "observed",
        asset_type="protocol",
        params={"enrichment": "partial", "enrichment_reason": "group not read"},
        locator="host:api-07:pid2231",
    )
    scored = apply_drift(_cbom_from(declared, [partial]))

    entries = _drifts(scored)
    kinds = {k for d in entries for k in d["ecdat:drift:kind"]}
    assert "declared-pqc-observed-unconfirmed" in kinds
    assert "declared-pqc-observed-classical" not in kinds
    assert any("0.5" in c for d in entries for c in d["ecdat:drift:confidence"])


# --------------------------------------------------------------------------
# The score
# --------------------------------------------------------------------------


def _key(finding: Finding) -> tuple[str, str, str]:
    return (file_of(finding), finding.algorithm, endpoint_of(finding))


def test_recall_and_precision(findings: list[Finding], capsys: Any) -> None:
    expected: Counter[tuple[str, str, str]] = Counter()
    for file_name, entries in EXPECTED.items():
        for entry in entries:
            expected[(file_name, entry["algorithm"], entry["endpoint"])] += entry[
                "count"
            ]

    actual: Counter[tuple[str, str, str]] = Counter(_key(f) for f in findings)

    planted = sum(expected.values())
    emitted = sum(actual.values())
    true_positives = sum(min(c, actual[k]) for k, c in expected.items())

    recall = true_positives / planted
    precision = true_positives / emitted if emitted else 0.0
    missed = sorted(str(k) for k, c in expected.items() if actual[k] < c)
    spurious = sorted(str(k) for k in actual if k not in expected)

    with capsys.disabled():
        print(f"\n  RECALL    {recall:6.1%}  ({true_positives}/{planted} planted)")
        print(f"  PRECISION {precision:6.1%}  ({true_positives}/{emitted} emitted)")
        if missed:
            print(f"  MISSED    {missed}")
        if spurious:
            print(f"  SPURIOUS  {spurious}")

    assert recall >= 0.9, f"recall {recall:.1%}; missed {missed}"
    assert precision == 1.0, f"precision {precision:.1%}; spurious {spurious}"
