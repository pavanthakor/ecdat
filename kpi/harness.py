"""Score ECDAT against QuantumBank, and print what it missed.

A benchmark number is only as trustworthy as its scorer, and a scorer is the
easiest thing in a project to make quietly generous. Three rules keep this one
honest:

* **A decoy firing is a PRECISION FAILURE, counted.** Not ignored as "not in
  the answer key". A false positive an operator chases and finds nothing behind
  is worse than a miss, because it spends their trust.
* **Known gaps are excluded from the denominator and PRINTED every run.** The
  QuantumBank fixture contains real cryptography ECDAT cannot see -- the Go
  gateway's ECDSA -- and leaving it out of the fixture would produce a better
  number by making the test easier. That is the oldest way to lie with a
  benchmark. A recall figure means nothing without the list of what it declined
  to measure.
* **Every miss is named.** Planted-but-not-found, fired-but-should-not-have,
  expected-drift-missing, invented-drift. The slide shows these.

The scoring arithmetic is separated from the scan so it can be tested directly
on synthetic inputs where the right answer is obvious.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

__all__ = [
    "DriftScore",
    "FindingScore",
    "KpiReport",
    "PlantedFinding",
    "load_answer_key",
    "run_kpi",
    "score_drift",
    "score_findings",
]

QUANTUMBANK = Path("testdata/quantumbank")
ANSWER_KEY = QUANTUMBANK / "answer_key.yaml"
SYSTEM = "quantumbank"

#: The gate. Printed alongside the actual numbers, which are shown regardless.
RECALL_GATE = 0.9
DECOY_PRECISION_GATE = 1.0


@dataclass(frozen=True, slots=True)
class PlantedFinding:
    """One artefact the fixture claims to contain."""

    id: str
    view: str
    algorithm: str
    locator_contains: str
    known_gap: bool = False
    note: str = ""


@dataclass
class ViewScore:
    planted: int = 0
    found: int = 0

    @property
    def recall(self) -> float:
        return self.found / self.planted if self.planted else 0.0


@dataclass
class FindingScore:
    """How much of the fixture was found, and what fired that should not have."""

    planted: int
    found: int
    emitted: int
    decoy_hits: int
    missed: list[PlantedFinding] = field(default_factory=list)
    known_gaps: list[PlantedFinding] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    by_view: dict[str, ViewScore] = field(default_factory=dict)

    @property
    def recall(self) -> float:
        """Over the CLAIMED-DETECTABLE set. Known gaps are not in the
        denominator, and are printed instead."""
        return self.found / self.planted if self.planted else 0.0

    @property
    def precision(self) -> float:
        """The fraction of emitted findings that did not come from a decoy.

        Decoys are the only measurable precision failure: the answer key lists
        planted artefacts, not every finding a real scan legitimately produces,
        so counting anything unlisted as false would punish correct detections
        the fixture happens not to enumerate.
        """
        if not self.emitted:
            return 0.0
        return (self.emitted - self.decoy_hits) / self.emitted


@dataclass
class ExpectedDrift:
    id: str
    kind: str
    endpoint: str


@dataclass
class DriftScore:
    expected: int
    found: int
    emitted: int
    missing: list[ExpectedDrift] = field(default_factory=list)
    invented: list[str] = field(default_factory=list)
    #: Drift that is neither expected nor invented -- a known consequence of
    #: the observed view carrying no endpoint (ADR-0012). Printed, and excluded
    #: from precision: scoring it correct would overstate the tool, scoring it
    #: invented would understate it, and neither is true.
    attribution_limited: list[str] = field(default_factory=list)

    @property
    def recall(self) -> float:
        return self.found / self.expected if self.expected else 1.0

    @property
    def precision(self) -> float:
        scored = self.emitted - len(self.attribution_limited)
        if scored <= 0:
            return 1.0
        return (scored - len(self.invented)) / scored


def load_answer_key(path: Path = ANSWER_KEY) -> dict[str, Any]:
    return dict(yaml.safe_load(path.read_text(encoding="utf-8")))


# ---------------------------------------------------------------------------
# Scoring -- pure, so it can be tested without running a scan
# ---------------------------------------------------------------------------


def _matches(emitted: dict[str, Any], planted: dict[str, Any]) -> bool:
    if emitted.get("view") != planted.get("view"):
        return False
    if emitted.get("algorithm") != planted.get("algorithm"):
        return False
    if str(planted.get("locator_contains", "")) not in str(emitted.get("locator", "")):
        return False
    wanted_type = planted.get("asset_type")
    if wanted_type and emitted.get("asset_type") != wanted_type:
        return False
    wanted_endpoint = planted.get("endpoint")
    return not (wanted_endpoint and emitted.get("endpoint") != wanted_endpoint)


def score_findings(
    emitted_findings: Sequence[dict[str, Any]],
    planted_findings: Sequence[dict[str, Any]],
    decoys: Sequence[str],
) -> FindingScore:
    """Recall over the claimed-detectable set; precision against the decoys."""
    missed: list[PlantedFinding] = []
    gaps: list[PlantedFinding] = []
    by_view: dict[str, ViewScore] = {}
    planted_count = 0
    found_count = 0

    for entry in planted_findings:
        record = PlantedFinding(
            id=str(entry["id"]),
            view=str(entry["view"]),
            algorithm=str(entry["algorithm"]),
            locator_contains=str(entry["locator_contains"]),
            known_gap=bool(entry.get("known_gap")),
            note=str(entry.get("note", "")),
        )
        if record.known_gap:
            # Excluded from the maths, never from the report.
            gaps.append(record)
            continue

        planted_count += 1
        view = by_view.setdefault(record.view, ViewScore())
        view.planted += 1

        if any(_matches(e, entry) for e in emitted_findings):
            found_count += 1
            view.found += 1
        else:
            missed.append(record)

    false_positives = [
        str(e.get("locator", ""))
        for e in emitted_findings
        if any(decoy in str(e.get("locator", "")) for decoy in decoys)
    ]

    return FindingScore(
        planted=planted_count,
        found=found_count,
        emitted=len(emitted_findings),
        decoy_hits=len(false_positives),
        missed=missed,
        known_gaps=gaps,
        false_positives=sorted(false_positives),
        by_view=by_view,
    )


def _drift_matches(emitted: dict[str, Any], expected: dict[str, Any]) -> bool:
    if emitted.get("kind") != expected.get("kind"):
        return False
    if emitted.get("endpoint") != expected.get("endpoint"):
        return False
    declared = expected.get("declared")
    if declared and emitted.get("declared") != declared:
        return False
    contains = expected.get("observed_contains")
    return not (contains and contains not in str(emitted.get("observed", "")))


def _limited(drift: dict[str, Any], limits: Sequence[dict[str, Any]]) -> bool:
    for limit in limits:
        if str(drift.get("endpoint", "")) != str(limit["endpoint"]):
            continue
        kind = limit.get("kind")
        if kind is None or drift.get("kind") == kind:
            return True
    return False


def score_drift(
    emitted_drifts: Sequence[dict[str, Any]],
    expected_drifts: Sequence[dict[str, Any]],
    non_drifts: Sequence[dict[str, Any]],
    attribution_limited: Sequence[dict[str, Any]] = (),
) -> DriftScore:
    """Drift recall against what must be found; precision against agreement."""
    missing: list[ExpectedDrift] = []
    found = 0

    for expected in expected_drifts:
        if any(_drift_matches(e, expected) for e in emitted_drifts):
            found += 1
        else:
            missing.append(
                ExpectedDrift(
                    id=str(expected["id"]),
                    kind=str(expected["kind"]),
                    endpoint=str(expected["endpoint"]),
                )
            )

    quiet = {str(entry["endpoint"]) for entry in non_drifts}
    matched = [
        d for d in emitted_drifts if any(_drift_matches(d, e) for e in expected_drifts)
    ]
    invented = sorted(
        f"{d.get('kind')} @ {d.get('endpoint')}"
        for d in emitted_drifts
        if str(d.get("endpoint", "")) in quiet
    )
    limited = sorted(
        f"{d.get('kind')} @ {d.get('endpoint')}"
        for d in emitted_drifts
        if d not in matched and _limited(d, attribution_limited)
    )

    return DriftScore(
        expected=len(expected_drifts),
        found=found,
        emitted=len(emitted_drifts),
        missing=missing,
        invented=invented,
        attribution_limited=limited,
    )


# ---------------------------------------------------------------------------
# Running the real thing
# ---------------------------------------------------------------------------


@dataclass
class KpiReport:
    findings: FindingScore
    drift: DriftScore
    emitted_drifts: list[dict[str, Any]]
    cbom_json: str
    components: int
    seconds: float

    @property
    def passes(self) -> bool:
        return (
            self.findings.recall >= RECALL_GATE
            and self.findings.decoy_hits == 0
            and self.drift.recall == 1.0
            and not self.drift.invented
        )

    def render(self) -> None:
        """The table, and then the misses. The misses are the honest part."""
        print()
        print("=" * 72)
        print(" ECDAT KPI -- QuantumBank")
        print("=" * 72)
        print(f"  components in CBOM : {self.components}")
        print(f"  scan time          : {self.seconds:.2f}s")
        print()
        print(f"  {'view':<12}{'planted':>9}{'found':>8}{'recall':>10}")
        print("  " + "-" * 39)
        for view in ("declared", "shipped", "observed"):
            score = self.findings.by_view.get(view)
            if score is None:
                continue
            print(f"  {view:<12}{score.planted:>9}{score.found:>8}{score.recall:>9.1%}")
        print("  " + "-" * 39)
        print(
            f"  {'OVERALL':<12}{self.findings.planted:>9}{self.findings.found:>8}"
            f"{self.findings.recall:>9.1%}"
        )
        print()
        print(
            f"  precision (decoys) : {self.findings.precision:.1%}  "
            f"({self.findings.decoy_hits} decoy hit(s) of "
            f"{self.findings.emitted} emitted)"
        )
        print(
            f"  drift recall       : {self.drift.recall:.1%}  "
            f"({self.drift.found}/{self.drift.expected} expected)"
        )
        print(
            f"  drift precision    : {self.drift.precision:.1%}  "
            f"({len(self.drift.invented)} invented of {self.drift.emitted})"
        )
        print()
        print(
            f"  GATE recall>={RECALL_GATE:.0%} and decoy-precision=="
            f"{DECOY_PRECISION_GATE:.0%}:  "
            f"{'PASS' if self.passes else 'FAIL'}"
        )

        print()
        print("  --- what was NOT found (planted, claimed detectable) ---")
        if self.findings.missed:
            for miss in self.findings.missed:
                where = miss.locator_contains
                print(f"    MISS  {miss.id}  ({miss.algorithm} in {where})")
        else:
            print("    (none)")

        print()
        print("  --- what fired that should not have (decoys) ---")
        if self.findings.false_positives:
            for locator in self.findings.false_positives:
                print(f"    FALSE POSITIVE  {locator}")
        else:
            print("    (none)")

        print()
        print("  --- drift ---")
        for entry in sorted(
            self.emitted_drifts, key=lambda d: (str(d["kind"]), str(d["endpoint"]))
        ):
            print(f"    FOUND    {entry['kind']} @ {entry['endpoint']}")
            print(f"             declared={entry['declared']}")
            print(f"             observed={entry['observed']}")
        for absent in self.drift.missing:
            print(f"    MISSING  {absent.id}: {absent.kind} @ {absent.endpoint}")
        for invented in self.drift.invented:
            print(f"    INVENTED {invented}")
        for limited in self.drift.attribution_limited:
            print(f"    UNATTRIBUTABLE {limited}")
            print("             (observed view carries no endpoint -- ADR-0012)")

        print()
        print("  --- KNOWN GAPS (planted, NOT counted against recall) ---")
        for gap in self.findings.known_gaps:
            print(f"    GAP  {gap.id}  ({gap.algorithm} in {gap.locator_contains})")
            print(f"         {gap.note.strip()}")
        print()


def _flatten(
    document: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Components as (findings, drifts) in the shape the scorer expects."""
    findings: list[dict[str, Any]] = []
    drifts: list[dict[str, Any]] = []

    for component in document.get("components", []):
        properties: dict[str, list[str]] = {}
        for prop in component.get("properties", []):
            properties.setdefault(prop["name"], []).append(prop["value"])

        params = {
            name.removeprefix("ecdat:param:"): values[0]
            for name, values in properties.items()
            if name.startswith("ecdat:param:")
        }
        view = properties.get("ecdat:view", [""])[0]
        endpoint = params.get("endpoint")

        for occurrence in component.get("evidence", {}).get("occurrences", []):
            findings.append(
                {
                    "algorithm": _algorithm_of(component),
                    "view": view,
                    "asset_type": properties.get("ecdat:asset_type", [""])[0],
                    "locator": str(occurrence.get("location", "")),
                    "endpoint": endpoint,
                }
            )

        for index, kind in enumerate(properties.get("ecdat:drift:kind", [])):
            drifts.append(
                {
                    "kind": kind,
                    "endpoint": endpoint,
                    "declared": properties.get("ecdat:drift:declared", [""])[index],
                    "observed": properties.get("ecdat:drift:observed", [""])[index],
                    "cause": properties.get("ecdat:drift:cause", [""])[index],
                }
            )

    return findings, drifts


def _algorithm_of(component: dict[str, Any]) -> str:
    """Recover the canonical algorithm from a component name.

    The same inverse the policy engine uses (ADR-0007): driven by the params,
    so ``SHA-1`` keeps its ``-1`` while ``RSA-2048`` loses its ``-2048``.
    """
    from policy.engine import component_facts

    return str(component_facts(component).get("algorithm", component.get("name", "")))


def run_kpi(root: Path = QUANTUMBANK) -> KpiReport:
    """Scan QuantumBank with every scanner and score the result.

    The spool is COPIED to a scratch directory first. The spool scanner moves
    ingested files into ``consumed/`` (ADR-0010), which is right for a real
    seam and would mutate a committed fixture -- so the KPI reads a copy and
    leaves the fixture pristine, which is also what makes two runs comparable.
    """
    from core import registry, store
    from core.orchestrator import run_scan
    from core.scanner import ScanContext, Target

    key = load_answer_key()
    started = time.monotonic()

    with tempfile.TemporaryDirectory(prefix="ecdat-kpi-") as workdir:
        scratch = Path(workdir)
        spool = scratch / "spool"
        shutil.copytree(root / "spool", spool)

        context = ScanContext(knowledge_dir=Path("knowledge"), scratch_dir=scratch)
        documents: list[dict[str, Any]] = []

        for kind, ref, scanners in (
            ("repo", str(root), ["source", "config"]),
            ("image", str(root / "images" / "payments.tar"), ["container"]),
            ("spool", str(spool), ["runtime-spool"]),
        ):
            target = Target(
                kind=kind,  # type: ignore[arg-type]
                ref=ref,
                system=SYSTEM,
                data_class="Personal",
                sector="bfsi",
                exposure="internet",
            )
            scan_id = run_scan(target, registry.get_scanners(scanners), context)
            record = store.get_scan(scan_id)
            assert record is not None  # noqa: S101 - just committed
            documents.append(json.loads(record.cbom_json))

    # One document, so the correlator can see all three views at once. Each
    # scan targets a different thing, and drift is a statement about a SYSTEM.
    merged = documents[0]
    merged.setdefault("metadata", {})["component"] = {
        "name": SYSTEM,
        "type": "application",
    }
    for extra in documents[1:]:
        merged["components"].extend(extra.get("components", []))

    from correlate.apply import apply_drift

    cbom_json = apply_drift(json.dumps(merged))
    document = json.loads(cbom_json)
    seconds = time.monotonic() - started

    emitted_findings, emitted_drifts = _flatten(document)

    return KpiReport(
        findings=score_findings(
            emitted_findings, key["findings"], key.get("decoys", [])
        ),
        drift=score_drift(
            emitted_drifts,
            key.get("drifts", []),
            key.get("non_drifts", []),
            key.get("attribution_limited", []),
        ),
        emitted_drifts=emitted_drifts,
        cbom_json=cbom_json,
        components=len(document.get("components", [])),
        seconds=seconds,
    )


def main() -> int:
    report = run_kpi()
    report.render()
    return 0 if report.passes else 1


if __name__ == "__main__":
    raise SystemExit(main())
