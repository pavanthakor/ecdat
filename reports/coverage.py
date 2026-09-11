"""The coverage statement: what ECDAT did NOT look at.

The honest artefact. Every other output says what was found; this one says what
could not have been found, and it is the one that stops a clean report being
read as a clean estate.

Two sources feed it, and neither is editorial:

* **what this scan actually did** -- `scanners_ran` (null = unknown, [] = none
  ran, ADR-0016), the views present in the document, and each component's
  `ecdat:coverage:missing`;
* **what ECDAT cannot do at all** -- the standing gap list below, which is the
  same list PUNCHLIST and the KPI harness print, kept here because a reader
  holding a PDF has neither.

A recall number is only meaningful beside the list of what it declined to
measure.
"""

from __future__ import annotations

from reports.layout import MUTED, Page
from reports.model import ALL_VIEWS, ScanView

__all__ = ["CoverageReport"]

#: What each view would have told us, so an absent one reads as a specific
#: gap rather than a missing word.
VIEW_MEANING = {
    "declared": "what the team says it uses — source, manifests, configuration",
    "shipped": "what actually got built — container images, binaries, certificates",
    "observed": "what a host was really doing — TLS handshakes seen at runtime",
}

#: How each view is collected, so "not collected" comes with its remedy.
VIEW_REMEDY = {
    "declared": "add a `repo` or `directory` target to the system manifest",
    "shipped": "add an `image` target (a `docker save` tar or OCI layout)",
    "observed": (
        "add a `spool` target — a directory the eBPF agent wrote "
        "(`make prove-pillar2` produces one)"
    ),
}

#: The standing limits. NOT derived from the scan: these hold for every scan
#: ECDAT runs today, and a report that omitted them would overstate the tool.
KNOWN_GAPS = [
    (
        "Source scanning covers Python, Go, JavaScript/TypeScript and Java",
        "C/C++, Rust and C# source are not scanned -- three of seven planned "
        "language families. C/C++ is the hard one: OpenSSL call sites are "
        "macro-heavy, so that pack needs a different engine rather than more "
        "rules (ADR-0023).",
    ),
    (
        "Binaries are read heuristically, and not inside container images",
        "The binary scanner (ADR-0025) reads ELF and PE files by symbols, OIDs, "
        "embedded PEM, version banners and known constants; every finding is "
        "confidence-scored and none is 1.0. A symbol proves a link, not a call; "
        "a stripped, statically linked or packed binary yields less; PE is read "
        "more shallowly than ELF, and Mach-O is untested. It is not wired to "
        "the container scanner, so an image scan inventories the installed "
        "packages, not the binaries inside the image.",
    ),
    (
        "There is no network scanner",
        "Six of a planned seven scanner families exist: source, configuration, "
        "dependency (Python, Node and Go manifests -- not Java or Rust), "
        "container, binary and the eBPF runtime view. No active TLS/SSH probe "
        "and no packet-capture reader exist, so an endpoint is seen only "
        "through its configuration or the runtime view.",
    ),
    (
        "Runtime coverage is narrower than 'TLS on this host'",
        "The eBPF probe attaches to libssl. Statically linked TLS, Go's "
        "crypto/tls, GnuTLS, NSS and mbedTLS are invisible to it, and it needs "
        "one attach per distinct libssl build in use.",
    ),
    (
        "Negotiated group is often unconfirmed rather than observed",
        "The accessor uretprobes only fire when a process asks libssl for its "
        "own parameters. A service that never logs its TLS parameters yields a "
        "partial observation, and ECDAT reports that rather than guessing.",
    ),
    (
        "An observed handshake carries no endpoint",
        "A uprobe sees a process, not a listening socket, so an observation "
        "joins every declared endpoint in its system. Drift attributed to a "
        "system with several differently-configured endpoints may name the "
        "wrong one.",
    ),
    (
        "Container layer whiteouts are ignored",
        "A file deleted in a later layer still produces a finding from the "
        "layer that introduced it. That is the right claim about what was "
        "SHIPPED and not the same as what is present in the running filesystem.",
    ),
    (
        "Some knowledge-pack facts remain unconfirmed",
        "The GnuTLS, libgcrypt and NSS post-quantum floors are unverified and "
        "therefore unscored. An unverified fact cannot move a score (ADR-0017), "
        "so those libraries are inventoried without a PQC verdict.",
    ),
]


class CoverageReport:
    """What was looked at, what was not, and what cannot be looked at."""

    kind = "coverage"
    title = "Coverage statement — what this scan did not look at"

    @staticmethod
    def render(page: Page, view: ScanView) -> None:
        scan = view.scan
        page.title(
            CoverageReport.title,
            f"{view.system} · scan {scan.id} · "
            f"{scan.created_at.isoformat(timespec='seconds')}",
        )
        page.body(
            "A finding count means nothing without the list of what it declined "
            "to measure. This statement is that list. Nothing here is inferred "
            "from the absence of findings — a view that was not collected is "
            "reported as not collected, never as clean.",
            colour=MUTED,
        )

        page.heading("Scanners")
        ran = scan.scanners_ran
        if ran is None:
            page.body(
                "UNKNOWN — this scan predates the scanners_ran column, so which "
                "plugins ran cannot be established from the record. Treat the "
                "inventory's completeness as unestablished.",
                colour=MUTED,
            )
        elif not ran:
            page.body(
                "NONE RAN. This row records an empty scanner set, so no view was "
                "collected by any plugin.",
                colour=MUTED,
            )
        else:
            for entry in ran:
                version = f" ({entry['version']})" if entry.get("version") else ""
                page.body(f"· {entry['id']}{version} — ran", size=8)
        page.space(2)
        page.kv("engine", _engines(view))

        page.heading("Views")
        for name in ALL_VIEWS:
            collected = name in view.views_present
            count = sum(1 for a in view.artefacts if a.view == name)
            if collected:
                page.body(
                    f"{name} — COLLECTED, {count} artefact(s). {VIEW_MEANING[name]}.",
                    size=8,
                )
            else:
                page.body(
                    f"{name} — NOT COLLECTED. {VIEW_MEANING[name]}. "
                    f"Nothing in this scan says anything about it; to collect it, "
                    f"{VIEW_REMEDY[name]}.",
                    size=8,
                    colour=MUTED,
                )
            page.space(2)

        gaps = _coverage_gaps(view)
        if gaps:
            page.heading("Components with an incomplete cross-view group")
            page.body(
                f"{len(gaps)} component(s) were correlated against a group that "
                f"was missing at least one view, so any drift verdict on them "
                f"rests on fewer sightings than a complete group would give.",
                colour=MUTED,
            )
            for name, missing in gaps[:12]:
                page.body(f"· {name} — missing {missing}", size=7.5, indent=10)
            if len(gaps) > 12:
                page.body(f"… and {len(gaps) - 12} more", size=7.5, indent=10)

        if view.provisional:
            page.heading("Facts displayed but not scored")
            page.body(
                f"{len(view.provisional)} artefact(s) carry at least one rule "
                f"that has not been confirmed against its source. Those rules "
                f"contributed 0 to every score in this scan and are shown as "
                f"provisional wherever they appear (ADR-0017).",
                colour=MUTED,
            )

        page.heading("What ECDAT cannot detect at all")
        page.body(
            "These limits hold for every scan, not just this one. They are "
            "printed on every coverage statement so a clean report is never "
            "mistaken for a complete one.",
            colour=MUTED,
        )
        page.space(3)
        for heading, detail in KNOWN_GAPS:
            page.room(34)
            page.body(heading, size=8.5, font="Helvetica-Bold")
            page.body(detail, size=7.5, colour=MUTED, indent=10)
            page.space(3)


def _coverage_gaps(view: ScanView) -> list[tuple[str, str]]:
    return [
        (a.name, ", ".join(a.coverage_missing))
        for a in sorted(view.artefacts, key=lambda a: a.rank)
        if a.coverage_missing
    ]


def _engines(view: ScanView) -> str:
    versions = view.scan.engine_versions or {}
    if not versions:
        return "not recorded for this scan"
    parts = []
    ecdat = versions.get("ecdat")
    if isinstance(ecdat, str):
        parts.append(f"ECDAT {ecdat}")
    for key, value in sorted(versions.items()):
        if key == "ecdat" or not isinstance(value, dict):
            continue
        engine = "semgrep" if key == "source" else key
        installed = value.get("installed") or "not installed"
        pinned = value.get("pinned")
        suffix = "" if installed == pinned else f" (pinned {pinned})"
        parts.append(f"{engine} {installed}{suffix}")
    return ", ".join(parts)
