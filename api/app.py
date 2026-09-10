"""The ECDAT HTTP API.

Thin by design: it runs the orchestrator and serves what the store holds. No
scanning logic, no scoring, no reshaping of the CBOM -- the document is handed
back as the exact bytes that were stored, because re-encoding it through a JSON
serialiser would quietly break the determinism guarantee ADR-0002 rests on.

``GET /scans`` reads its verdict summary from DENORMALISED COLUMNS and never
parses a stored document (ADR-0016). It used to parse every CBOM on every
request, which is O(scans x document size) for a bar chart. The test that
defends this corrupts a stored document and asserts the summary is unchanged --
a regression to parsing cannot pass it.

``POST /scans/{id}/fix`` and ``POST /scans/{id}/rescore`` write NEW rows linked
to their parent. Neither amends the scan it derives from.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Literal

from fastapi import FastAPI, HTTPException, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from core import registry, store
from core.logs import configure_logging, get_logger
from core.orchestrator import (
    UnknownScanError,
    UnscannableTargetError,
    default_context,
    run_fix,
    run_rescore,
    run_scan,
)
from core.scanner import Target
from core.summary import BAND_NAMES, VerdictSummary
from policy.apply import DEFAULT_Z_YEARS

__all__ = ["app"]

_log = get_logger("api")

#: The dashboard runs on a Vite dev server; nothing else needs cross-origin
#: access. Kept to explicit localhost origins rather than "*" -- the API will
#: serve an estate's full cryptographic inventory.
LOCAL_DASHBOARD_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]


class TargetIn(BaseModel):
    """A thing to scan, as the dashboard describes it."""

    kind: Literal["repo", "directory", "image", "host", "endpoint", "spool"]
    ref: str = Field(min_length=1)
    system: str | None = None
    data_class: str | None = None
    #: Which sector this target serves. Drives the DST roadmap's earlier
    #: critical-information-infrastructure deadline.
    sector: Literal[
        "government",
        "strategic",
        "defence",
        "power",
        "telecom",
        "transport",
        "bfsi",
        "other",
    ] = "other"
    #: How reachable the target is. Feeds blast-radius prioritisation.
    exposure: Literal["internet", "internal", "build", "unknown"] = "unknown"
    #: Years until a cryptographically relevant quantum computer. A global
    #: assumption, not a measurement -- the dashboard exposes it as a slider so
    #: an analyst can re-prioritise the estate against a different horizon.
    z_years: int = Field(default=DEFAULT_Z_YEARS, ge=0, le=100)
    #: Which plugins to run. Omitted (``None``) means every registered scanner,
    #: which is the normal case. An explicit list selects a subset -- and an
    #: explicit empty list selects none, which is honoured rather than treated
    #: as "unset", so a caller can ask for a scan that detects nothing.
    scanners: list[str] | None = None


class ScanCreated(BaseModel):
    scan_id: str
    component_count: int


class TargetOut(BaseModel):
    kind: str
    ref: str
    system: str | None
    data_class: str | None


class ScanSummary(BaseModel):
    id: str
    target: TargetOut
    created_at: datetime
    component_count: int
    #: How many components landed in each policy band, e.g.
    #: ``{"Critical": 0, "High": 0, "Medium": 3, "Low": 4}``. Read back out of
    #: the stored CBOM rather than recomputed, so the dashboard sees exactly
    #: the verdicts that were stored.
    band_counts: dict[str, int]
    #: The highest component score in the scan; 0 for an empty CBOM.
    max_score: int
    #: How many components carry drift, by kind. Empty when the views agree --
    #: or when only one view was scanned, which `coverage_gaps` reports
    #: separately, because "they agree" and "we did not look" are different
    #: answers (ADR-0012).
    drift_counts: dict[str, int]
    #: Components whose correlation group was missing a view.
    coverage_gaps: int
    #: What this row was produced by: ``scan``, ``fix`` or ``rescore``.
    kind: str
    #: The scan a ``fix``/``rescore`` row was derived from; ``None`` for a scan.
    parent_scan_id: str | None
    #: Which plugins ran. ``null`` = UNKNOWN (a row written before the column
    #: existed); ``[]`` = known, and nothing ran. A dashboard MUST render these
    #: differently: "never looked for binaries" is not "binaries were clean".
    scanners_ran: list[dict[str, str]] | None
    #: The context the scan was scored in, so a viewer can see why a component
    #: scored what it did -- and `null` where it was never recorded.
    sector: str | None
    exposure: str | None
    z_years: int | None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:  # noqa: ARG001
    configure_logging()
    store.init_db()
    _log.info("api_started", extra={"event": "api_started"})
    yield


app = FastAPI(
    title="ECDAT",
    version="0.1.0",
    summary="Enterprise Cryptographic Discovery & Analysis Tool",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=LOCAL_DASHBOARD_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/scanners")
def list_scanners() -> list[str]:
    """Every scanner the server can run, for the dashboard to offer."""
    return registry.available_ids()


@app.post("/scans", status_code=status.HTTP_201_CREATED)
def create_scan(body: TargetIn) -> ScanCreated:
    try:
        scanners = registry.get_scanners(body.scanners)
    except registry.UnknownScannerError as exc:
        # A typo in a scanner id is the client's mistake, and silently running
        # the wrong set would be worse than refusing: a scan that quietly
        # skipped a whole view still looks like a clean inventory.
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    target = Target(
        kind=body.kind,
        ref=body.ref,
        system=body.system,
        data_class=body.data_class,
        sector=body.sector,
        exposure=body.exposure,
    )
    scan_id = run_scan(target, scanners, default_context(), z_years=body.z_years)
    scan = store.get_scan(scan_id)
    if scan is None:  # pragma: no cover - the row was just committed
        raise HTTPException(status_code=500, detail="scan disappeared after saving")
    return ScanCreated(scan_id=scan.id, component_count=scan.component_count)


def _summary_for(scan: store.Scan) -> VerdictSummary:
    """The verdict summary, off the row's columns. NEVER parses the CBOM.

    The store computes this once at save time beside the bytes it describes, so
    the two cannot disagree, and the migration backfills it for rows written
    before the columns existed. A row whose summary is still NULL is one whose
    document could not be parsed at migration time; it reports zeroes rather
    than being silently re-derived here, because re-deriving is exactly the
    per-request parse this function exists to remove.
    """
    return VerdictSummary(
        band_counts=scan.band_counts or dict.fromkeys(BAND_NAMES, 0),
        max_score=scan.max_score or 0,
        drift_counts=scan.drift_counts or {},
        coverage_gaps=scan.coverage_gaps or 0,
    )


def _summarise(scan: store.Scan) -> ScanSummary:
    summary = _summary_for(scan)
    return ScanSummary(
        id=scan.id,
        target=TargetOut(
            kind=scan.target_kind,
            ref=scan.target_ref,
            system=scan.target_system,
            data_class=scan.target_data_class,
        ),
        created_at=scan.created_at,
        component_count=scan.component_count,
        band_counts=summary.band_counts,
        max_score=summary.max_score,
        drift_counts=summary.drift_counts,
        coverage_gaps=summary.coverage_gaps,
        kind=scan.kind,
        parent_scan_id=scan.parent_scan_id,
        scanners_ran=scan.scanners_ran,
        sector=scan.sector,
        exposure=scan.exposure,
        z_years=scan.z_years,
    )


@app.get("/scans")
def list_scans(kind: str | None = None) -> list[ScanSummary]:
    """Every row, newest first. Derived rows are listed, not hidden.

    ``kind`` narrows to ``scan``, ``fix`` or ``rescore``. Omitting it returns
    everything: a fix pass that produced no visible row would be a change the
    operator cannot see they made.
    """
    return [_summarise(scan) for scan in store.list_scans(kind=kind)]


@app.get("/scans/{scan_id}/cbom")
def get_cbom(scan_id: str) -> Response:
    scan = store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"no scan with id {scan_id!r}")
    # Verbatim bytes: see the module docstring.
    return Response(content=scan.cbom_json, media_type="application/json")


# ---------------------------------------------------------------------------
# Derived passes: fix and rescore (ADR-0016)
#
# Both write a NEW row linked by parent_scan_id. Neither amends the scan it
# derives from -- the API cannot revise an inventory, only add to its history.
# ---------------------------------------------------------------------------


class FixIn(BaseModel):
    """Options for a fix pass. Every field is an OVERRIDE, not a default.

    Omitted fields fall back to the context recorded on the parent scan, which
    is what stops a fix being judged more leniently than the scan that found
    the problem.
    """

    scanners: list[str] | None = None
    sector: (
        Literal[
            "government",
            "strategic",
            "defence",
            "power",
            "telecom",
            "transport",
            "bfsi",
            "other",
        ]
        | None
    ) = None
    exposure: Literal["internet", "internal", "build", "unknown"] | None = None
    z_years: int | None = Field(default=None, ge=0, le=100)


class DerivedCreated(BaseModel):
    scan_id: str
    parent_scan_id: str
    kind: str


class FixOut(BaseModel):
    """One component's fix result, as the dashboard renders it."""

    bom_ref: str
    component: str
    template: str
    verified: bool
    reason: str
    source: str | None = None
    #: Present ONLY when ``verified`` is true. An unverified patch rendered
    #: next to an apply button is how an unproven change reaches production
    #: (ADR-0015), so the invariant is carried through to the wire.
    diff: str | None = None


class FixesOut(BaseModel):
    parent_scan_id: str
    #: The most recent fix row, or ``None`` if no fix pass has been run.
    fix_scan_id: str | None
    created_at: datetime | None
    fixes: list[FixOut]


@app.post("/scans/{scan_id}/fix", status_code=status.HTTP_201_CREATED)
def create_fix(scan_id: str, body: FixIn) -> DerivedCreated:
    """Propose verified fixes for a stored scan and persist them as a new row.

    Synchronous, like ``POST /scans`` -- and slower, because verifying a fix
    copies the target and re-scans it twice per finding. Both want the job
    model the punch-list already owes.
    """
    if store.get_scan(scan_id) is None:
        raise HTTPException(status_code=404, detail=f"no scan with id {scan_id!r}")
    try:
        scanners = registry.get_scanners(body.scanners)
    except registry.UnknownScannerError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        run = run_fix(
            scan_id,
            scanners,
            default_context(),
            sector=body.sector,
            exposure=body.exposure,
            z_years=body.z_years,
        )
    except UnknownScanError as exc:  # pragma: no cover - checked above
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except UnscannableTargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return DerivedCreated(
        scan_id=run.scan_id, parent_scan_id=scan_id, kind=store.KIND_FIX
    )


@app.get("/scans/{scan_id}/fixes")
def get_fixes(scan_id: str) -> FixesOut:
    """The fix results for a scan, read off its most recent fix row."""
    if store.get_scan(scan_id) is None:
        raise HTTPException(status_code=404, detail=f"no scan with id {scan_id!r}")

    row = store.latest_child(scan_id, kind=store.KIND_FIX)
    if row is None:
        return FixesOut(
            parent_scan_id=scan_id, fix_scan_id=None, created_at=None, fixes=[]
        )

    fixes: list[FixOut] = []
    for component in json.loads(row.cbom_json).get("components", []):
        values: dict[str, str] = {
            p["name"]: p["value"] for p in component.get("properties", [])
        }
        template = values.get("ecdat:fix:template")
        if template is None:
            continue
        fixes.append(
            FixOut(
                bom_ref=str(component.get("bom-ref", "")),
                component=str(component.get("name", "")),
                template=template,
                verified=values.get("ecdat:fix:verified") == "true",
                reason=values.get("ecdat:fix:reason", ""),
                source=values.get("ecdat:fix:source"),
                diff=values.get("ecdat:fix:diff"),
            )
        )
    fixes.sort(key=lambda entry: (entry.template, entry.bom_ref))
    return FixesOut(
        parent_scan_id=scan_id,
        fix_scan_id=row.id,
        created_at=row.created_at,
        fixes=fixes,
    )


@app.post("/scans/{scan_id}/rescore", status_code=status.HTTP_201_CREATED)
def create_rescore(scan_id: str, z_years: int | None = None) -> DerivedCreated:
    """Re-score a stored CBOM under a new CRQC horizon. Runs no scanner.

    This is what the dashboard's Mosca slider calls. The original verdict stays
    on the record beside the new one, so "we re-prioritised in March" is an
    auditable statement rather than a silently different number.
    """
    if store.get_scan(scan_id) is None:
        raise HTTPException(status_code=404, detail=f"no scan with id {scan_id!r}")
    if z_years is not None and not 0 <= z_years <= 100:
        raise HTTPException(status_code=422, detail="z_years must be within [0, 100]")

    try:
        new_id = run_rescore(scan_id, default_context(), z_years=z_years)
    except UnknownScanError as exc:  # pragma: no cover - checked above
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return DerivedCreated(
        scan_id=new_id, parent_scan_id=scan_id, kind=store.KIND_RESCORE
    )
