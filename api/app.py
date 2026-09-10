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

ADR-0035 hardened the surface:

* **Keys.** Every route but ``/health`` and the console's static files needs an
  API key (``api/auth.py``). A viewer reads; an admin can also start work that
  reads a target, and read the verified patches. Each route declares its
  guard, and tests/test_api_auth.py reads the routes to prove none is missing.
* **Jobs.** A scan, a system scan and a fix pass answer 202 with a job id and
  run on a worker thread (``api/jobs.py``); ``GET /jobs/{id}`` tracks them.
  ``?wait=true`` keeps the synchronous path. The REQUEST is validated before
  anything is queued, so a bad request is still refused at once.
* **Pages.** ``GET /scans`` and ``GET /jobs`` answer one page and the total.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Generic, Literal, TypeVar

from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from api import auth
from api.jobs import (
    INTERRUPTED_AT_START,
    JobRunner,
    describe_failure,
    execute,
    worker_count,
)
from core import registry, store
from core.compare import compare_documents
from core.logs import configure_logging, get_logger
from core.orchestrator import (
    UnknownScanError,
    UnscannableTargetError,
    default_context,
    run_fix,
    run_rescore,
    run_scan,
    target_kind_of,
)
from core.scanner import Target
from core.summary import BAND_NAMES, VerdictSummary
from core.system import ManifestError, TargetUnreadableError, parse_manifest
from core.system import scan_system as run_system_scan
from policy.apply import DEFAULT_Z_YEARS

__all__ = ["DEFAULT_PAGE_SIZE", "MAX_PAGE_SIZE", "app"]

_log = get_logger("api")

#: The built console. `make web` produces it; FastAPI serves it as static
#: files so the demo machine runs no Node at all (ADR-0018).
WEB_DIST = Path(__file__).resolve().parent.parent / "web" / "dist"

#: Path prefixes that belong to the API. The SPA catch-all must 404 inside
#: these rather than hand back index.html -- an HTML 200 for a mistyped
#: endpoint is the bug where a fetch "succeeds" and JSON.parse explodes three
#: frames away.
API_PREFIXES = (
    "api",
    "auth",
    "jobs",
    "scans",
    "scanners",
    "systems",
    "health",
    "docs",
    "redoc",
    "openapi.json",
)

#: A page of a list that grows with use (ADR-0035). Fifty rows is a screenful
#: of scan history; five hundred bounds what one request can make the server
#: serialise.
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 500

#: What a job runs. The API's vocabulary; the store keeps it as a plain string.
JOB_SCAN = "scan"
JOB_SYSTEM_SCAN = "system-scan"
JOB_FIX = "fix"

#: The guards. Every route declares exactly one of these -- or an
#: ``auth.Admin`` / ``auth.Viewer`` parameter when it needs to know who asked.
READ = [Depends(auth.require_viewer)]
ADMIN = [Depends(auth.require_admin)]

Limit = Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE, description="rows per page")]
Offset = Annotated[int, Query(ge=0, description="rows to skip")]
#: ``?wait=true`` runs the job inside the request and answers 201 with its
#: result: the synchronous path, for scripts and tests. It is still a job.
Wait = Annotated[
    bool, Query(description="run synchronously; answer 201 with the result")
]

#: Every route is defined once here and mounted twice: bare (the documented
#: surface) and under `/api` (what the console fetches, matching the Vite dev
#: proxy). Neither is a redirect, so both work offline and without rewriting.
router = APIRouter()

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
    #: The job that ran it. A synchronous (``?wait=true``) scan is still a job.
    job_id: str | None = None


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
    #: Which engine produced this scan (ADR-0017), so the console footer can
    #: say what a reader is looking at. `null` on a row written before the
    #: column existed.
    engine_versions: dict[str, Any] | None
    #: Set when an installed engine differed from the pinned one.
    engine_warning: str | None


T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    """One page of a list, newest first (ADR-0035)."""

    items: list[T]
    #: Every row the filter matches -- not just this page's.
    total: int
    limit: int
    offset: int


class JobAccepted(BaseModel):
    """The 202 body: the work is queued; watch it at ``GET /jobs/{job_id}``."""

    job_id: str
    kind: str
    #: As accepted. A worker may already have picked it up; ask the job.
    status: str


class JobOut(BaseModel):
    id: str
    kind: str
    #: ``pending``, ``running``, ``done`` or ``failed``.
    status: str
    subject: str
    parent_scan_id: str | None
    #: The stored row, once ``done``; ``None`` otherwise.
    scan_id: str | None
    #: Why it failed, once ``failed``; ``None`` otherwise.
    error: str | None
    #: The NAME of the key that asked.
    requested_by: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class PrincipalOut(BaseModel):
    name: str
    role: str


def _key_count() -> int | None:
    """How many keys the server will accept; ``None`` if the file is unusable."""
    try:
        return len(auth.load_keys())
    except auth.KeyFileError:
        return None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    store.init_db()
    # Jobs die with the process that ran them (api/jobs.py). Anything still
    # pending or running now was interrupted, and must not say otherwise.
    interrupted = store.fail_unfinished_jobs(INTERRUPTED_AT_START)
    runner = JobRunner(worker_count())
    app.state.jobs = runner
    keys = _key_count()
    # The absolute path, because "the dashboard is empty" is almost always
    # "the server opened a different file than the scan wrote to" (ADR-0020).
    _log.info(
        "api_started",
        extra={
            "event": "api_started",
            "database": str(store.database_location()),
            "console": "built" if WEB_DIST.is_dir() else "not built",
            "api_keys": str(auth.keys_path()),
            "api_key_count": keys,
            "job_workers": runner.workers,
            "jobs_interrupted": len(interrupted),
        },
    )
    if not keys:
        _log.warning(
            "api_keys_unusable",
            extra={
                "event": "api_keys_unusable",
                "api_keys": str(auth.keys_path()),
                "detail": (
                    "no usable API key: every data request will be refused. "
                    "Issue one with `ecdat api-key create --name <who> --role admin`."
                ),
            },
        )
    try:
        yield
    finally:
        runner.shutdown()


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


@router.get("/health")
def health() -> dict[str, str]:
    """Liveness. Open: it says the process is up, and nothing else."""
    return {"status": "ok"}


@router.get("/auth/whoami")
def whoami(principal: auth.Viewer) -> PrincipalOut:
    """Which key this is, and its role. The console checks a key here first."""
    return PrincipalOut(name=principal.name, role=principal.role)


@router.get("/scanners", dependencies=READ)
def list_scanners() -> list[str]:
    """Every scanner the server can run, for the dashboard to offer."""
    return registry.available_ids()


# ---------------------------------------------------------------------------
# Jobs (ADR-0035)
# ---------------------------------------------------------------------------

#: The two answers a job-starting route can give.
ACCEPTED_OR_CREATED: dict[int | str, dict[str, Any]] = {
    201: {
        "description": "`?wait=true`: the job ran in this request; its row is stored"
    },
    202: {"description": "queued as a job; poll `GET /jobs/{job_id}` (see Location)"},
}


def _job_out(job: store.Job) -> JobOut:
    return JobOut(
        id=job.id,
        kind=job.kind,
        status=job.status,
        subject=job.subject,
        parent_scan_id=job.parent_scan_id,
        scan_id=job.scan_id,
        error=job.error,
        requested_by=job.requested_by,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
    )


def _accept(
    request: Request,
    response: Response,
    job_id: str,
    kind: str,
    work: Callable[[], str],
) -> JobAccepted:
    """Queue the work and answer 202, pointing at where to watch it."""
    runner: JobRunner | None = getattr(request.app.state, "jobs", None)
    if runner is None:  # pragma: no cover - only outside the app's lifespan
        store.mark_job_failed(job_id, "the job runner is not running")
        raise HTTPException(status_code=503, detail="the job runner is not running")
    runner.submit(job_id, work)
    mount = "/api" if request.url.path.startswith("/api/") else ""
    response.headers["Location"] = f"{mount}/jobs/{job_id}"
    return JobAccepted(job_id=job_id, kind=kind, status=store.JOB_PENDING)


def _run_now(job_id: str, work: Callable[[], str]) -> str:
    """``?wait=true``: run the job in this request; a failure is an HTTP error.

    The operator's own mistakes keep the 400 they had before the job model;
    anything else is a 500 carrying the reason the job records.
    """
    try:
        return execute(job_id, work)
    except (UnscannableTargetError, TargetUnreadableError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"job {job_id} failed: {describe_failure(exc)}"
        ) from exc


def _created(scan_id: str, job_id: str) -> ScanCreated:
    scan = store.get_scan(scan_id)
    if scan is None:  # pragma: no cover - the row was just committed
        raise HTTPException(status_code=500, detail="scan disappeared after saving")
    return ScanCreated(
        scan_id=scan.id, component_count=scan.component_count, job_id=job_id
    )


@router.get("/jobs", dependencies=READ)
def list_jobs(limit: Limit = DEFAULT_PAGE_SIZE, offset: Offset = 0) -> Page[JobOut]:
    """Every job, newest first -- failed ones included, with their reasons."""
    return Page[JobOut](
        items=[_job_out(job) for job in store.list_jobs(limit=limit, offset=offset)],
        total=store.count_jobs(),
        limit=limit,
        offset=offset,
    )


@router.get("/jobs/{job_id}", dependencies=READ)
def get_job(job_id: str) -> JobOut:
    """Pending, running, done (with the scan id) or failed (with the reason).

    Open to a viewer: watching work is reading.
    """
    job = store.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"no job with id {job_id!r}")
    return _job_out(job)


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


@router.post(
    "/scans", status_code=status.HTTP_202_ACCEPTED, responses=ACCEPTED_OR_CREATED
)
def create_scan(
    body: TargetIn,
    principal: auth.Admin,
    request: Request,
    response: Response,
    wait: Wait = False,
) -> JobAccepted | ScanCreated:
    """Scan one target, as a job. Admin: it makes the server read a target."""
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
    job_id = store.create_job(
        JOB_SCAN, subject=f"{target.kind} {target.ref}", requested_by=principal.name
    )

    def work() -> str:
        return run_scan(target, scanners, default_context(), z_years=body.z_years)

    if not wait:
        return _accept(request, response, job_id, JOB_SCAN, work)
    scan_id = _run_now(job_id, work)
    response.status_code = status.HTTP_201_CREATED
    return _created(scan_id, job_id)


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
        engine_versions=scan.engine_versions,
        engine_warning=scan.engine_warning,
    )


@router.get("/scans", dependencies=READ)
def list_scans(
    kind: str | None = None,
    limit: Limit = DEFAULT_PAGE_SIZE,
    offset: Offset = 0,
) -> Page[ScanSummary]:
    """One page of rows, newest first. Derived rows are listed, not hidden.

    ``kind`` narrows to ``scan``, ``fix`` or ``rescore``. Omitting it returns
    everything: a fix pass that produced no visible row would be a change the
    operator cannot see they made. ``total`` counts every matching row, so a
    client knows where the list ends without fetching it.
    """
    rows = store.list_scans(kind=kind, limit=limit, offset=offset)
    return Page[ScanSummary](
        items=[_summarise(scan) for scan in rows],
        total=store.count_scans(kind=kind),
        limit=limit,
        offset=offset,
    )


@router.get("/scans/{scan_id}", dependencies=READ)
def get_scan(scan_id: str) -> ScanSummary:
    """One row's summary, off the denormalised columns (ADR-0016).

    The console calls this after a rescore rather than re-listing the estate:
    a derived row is new, and listing every scan to find one id gets slower
    with every pass a user runs.
    """
    scan = store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"no scan with id {scan_id!r}")
    return _summarise(scan)


@router.get("/scans/{scan_id}/cbom", dependencies=READ)
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
    #: The job, for a fix pass run with ``?wait=true``. A rescore is not a job.
    job_id: str | None = None


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


@router.post(
    "/scans/{scan_id}/fix",
    status_code=status.HTTP_202_ACCEPTED,
    responses=ACCEPTED_OR_CREATED,
)
def create_fix(
    scan_id: str,
    body: FixIn,
    principal: auth.Admin,
    request: Request,
    response: Response,
    wait: Wait = False,
) -> JobAccepted | DerivedCreated:
    """Propose verified fixes for a stored scan, as a job; they land as a NEW row.

    A job because it is slow: verifying a fix copies the target and re-scans
    it twice per finding.
    """
    parent = store.get_scan(scan_id)
    if parent is None:
        raise HTTPException(status_code=404, detail=f"no scan with id {scan_id!r}")
    if target_kind_of(parent.target_kind) is None:
        # A fact about the stored ROW, known now: queueing a job that can
        # only fail would turn an immediate answer into a delayed one.
        raise HTTPException(
            status_code=400,
            detail=(
                f"scan {scan_id} records target kind {parent.target_kind!r}, which "
                "is not a kind ECDAT knows about; there is no target to re-scan"
            ),
        )
    try:
        scanners = registry.get_scanners(body.scanners)
    except registry.UnknownScannerError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    job_id = store.create_job(
        JOB_FIX,
        subject=f"{parent.target_kind} {parent.target_ref}",
        parent_scan_id=scan_id,
        requested_by=principal.name,
    )

    def work() -> str:
        return run_fix(
            scan_id,
            scanners,
            default_context(),
            sector=body.sector,
            exposure=body.exposure,
            z_years=body.z_years,
        ).scan_id

    if not wait:
        return _accept(request, response, job_id, JOB_FIX, work)
    fix_id = _run_now(job_id, work)
    response.status_code = status.HTTP_201_CREATED
    return DerivedCreated(
        scan_id=fix_id, parent_scan_id=scan_id, kind=store.KIND_FIX, job_id=job_id
    )


@router.get("/scans/{scan_id}/fixes", dependencies=ADMIN)
def get_fixes(scan_id: str) -> FixesOut:
    """The fix results for a scan, read off its most recent fix row.

    Admin only: verified patches for an estate's weakest cryptography are the
    most sensitive thing this API serves (ADR-0035).
    """
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


@router.post(
    "/scans/{scan_id}/rescore",
    status_code=status.HTTP_201_CREATED,
    dependencies=READ,
)
def create_rescore(scan_id: str, z_years: int | None = None) -> DerivedCreated:
    """Re-score a stored CBOM under a new CRQC horizon. Runs no scanner.

    This is what the dashboard's Mosca slider calls. The original verdict stays
    on the record beside the new one, so "we re-prioritised in March" is an
    auditable statement rather than a silently different number.

    Open to a VIEWER (ADR-0035): it reads no target and runs no scanner, only
    re-scores bytes already stored, and a console a viewer cannot drag the
    slider in is half a console. It does add a derived row -- history, never
    an edit of any scan. Synchronous: it is a re-score, not a scan.
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


# ---------------------------------------------------------------------------
# Compare two stored scans (ADR-0031)
# ---------------------------------------------------------------------------


class ScanRefOut(BaseModel):
    id: str
    kind: str
    created_at: datetime
    system: str | None


class VerdictOut(BaseModel):
    band: str | None
    score: int | None
    deadline: str | None
    quantum_status: str | None


class CompareEntryOut(BaseModel):
    bom_ref: str
    name: str
    band: str | None
    score: int | None
    deadline: str | None


class CompareChangeOut(BaseModel):
    bom_ref: str
    name: str
    #: Which of band/score/deadline/quantum_status/evidence differ.
    fields: list[str]
    before: VerdictOut
    after: VerdictOut
    evidence_added: list[str]
    evidence_removed: list[str]


class CompareDriftOut(BaseModel):
    bom_ref: str
    name: str
    kind: str
    declared: str
    observed: str
    cause: str


class CompareOut(BaseModel):
    base: ScanRefOut
    head: ScanRefOut
    new: list[CompareEntryOut]
    resolved: list[CompareEntryOut]
    changed: list[CompareChangeOut]
    drift_introduced: list[CompareDriftOut]
    drift_resolved: list[CompareDriftOut]
    unchanged: int


def _scan_ref(scan: store.Scan) -> ScanRefOut:
    return ScanRefOut(
        id=scan.id,
        kind=scan.kind,
        created_at=scan.created_at,
        system=scan.target_system,
    )


@router.get("/scans/{scan_id}/compare/{other_id}", dependencies=READ)
def compare_scans(scan_id: str, other_id: str) -> CompareOut:
    """What changed from ``scan_id`` (base) to ``other_id`` (head).

    Joined on the content-addressed bom-ref, so it is exact within what the
    identity can join: a moved line is changed evidence, a new sighting place
    is resolved + new (see ``core.compare``). Parses both stored documents --
    a detail view, not a list, so ADR-0016's no-parse rule is not in play.
    """
    rows: list[store.Scan] = []
    for wanted in (scan_id, other_id):
        row = store.get_scan(wanted)
        if row is None:
            raise HTTPException(status_code=404, detail=f"no scan with id {wanted!r}")
        rows.append(row)
    base, head = rows

    result = compare_documents(json.loads(base.cbom_json), json.loads(head.cbom_json))
    return CompareOut.model_validate(
        {**asdict(result), "base": _scan_ref(base), "head": _scan_ref(head)}
    )


# ---------------------------------------------------------------------------
# System scan: three views into one document (ADR-0019)
# ---------------------------------------------------------------------------


class SystemTargetIn(BaseModel):
    #: Deliberately `str`, not a Literal. See SystemManifestIn.
    kind: str
    ref: str


class SystemManifestIn(BaseModel):
    """A system manifest, as JSON. The same shape the YAML file carries.

    **The vocabularies are typed as plain strings on purpose.** Validation is
    `core.system.parse_manifest`, and it is the ONLY manifest validator --
    a Literal here would refuse a bad `kind` with FastAPI's own 422 before
    ECDAT's checker ran, which means two validators that can disagree and a
    manifest that loads from a file but not from the API. One validator, one
    message, identical refusals from the CLI and the API.
    """

    system: str = ""
    targets: list[SystemTargetIn] = Field(default_factory=list)
    sector: str = "other"
    exposure: str = "unknown"
    data_class: str | None = None
    z_years: int = Field(default=DEFAULT_Z_YEARS, ge=0, le=100)


@router.post(
    "/systems/scan",
    status_code=status.HTTP_202_ACCEPTED,
    responses=ACCEPTED_OR_CREATED,
)
def create_system_scan(
    body: SystemManifestIn,
    principal: auth.Admin,
    request: Request,
    response: Response,
    wait: Wait = False,
) -> JobAccepted | ScanCreated:
    """Scan every target in a manifest into ONE correlated CBOM, as a job.

    The manifest is validated now, before anything is queued. The targets are
    READ by the job, so a missing image fails the job, naming the image --
    the request itself was well-formed.
    """
    try:
        manifest = parse_manifest(body.model_dump(exclude={"z_years"}))
    except ManifestError as exc:
        # A malformed manifest is the client's mistake, and refusing names the
        # target that was wrong rather than silently scanning fewer views.
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    job_id = store.create_job(
        JOB_SYSTEM_SCAN,
        subject=f"system {manifest.system}",
        requested_by=principal.name,
    )

    def work() -> str:
        return run_system_scan(manifest, default_context(), z_years=body.z_years)

    if not wait:
        return _accept(request, response, job_id, JOB_SYSTEM_SCAN, work)
    scan_id = _run_now(job_id, work)
    response.status_code = status.HTTP_201_CREATED
    return _created(scan_id, job_id)


# ---------------------------------------------------------------------------
# Reports: PDFs rendered from a stored scan (ADR-0020)
# ---------------------------------------------------------------------------


@router.get(
    "/scans/{scan_id}/report/{kind}",
    response_class=Response,
    responses={200: {"content": {"application/pdf": {}}}},
    dependencies=READ,
)
def get_report(scan_id: str, kind: str) -> Response:
    """Render one of the three reports for a stored scan.

    Nothing is re-scanned: the PDF is a projection of the CBOM already on the
    row, so it cannot disagree with what the dashboard shows for the same scan.
    """
    from reports import UnknownScanError, render, report_for

    try:
        report = report_for(kind)
    except ValueError as exc:
        # Names the kinds that DO exist rather than 404ing into silence.
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        payload = render(report, scan_id)
    except UnknownScanError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return Response(
        content=payload,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'inline; filename="ecdat-{kind}-{scan_id[:8]}.pdf"'
            )
        },
    )


# ---------------------------------------------------------------------------
# Mounting: the API twice, then the console (ADR-0018)
#
# ORDER MATTERS. The API routers are included before the SPA catch-all, so a
# real endpoint always wins; the catch-all only sees paths nothing else
# claimed.
# ---------------------------------------------------------------------------

app.include_router(router)
# The console fetches `/api/...` -- the same path the Vite dev proxy forwards,
# so one client works both in `npm run dev` and against the built bundle.
# Hidden from the schema: it is the same surface, not a second one.
app.include_router(router, prefix="/api", include_in_schema=False)


if WEB_DIST.is_dir():
    # Hashed bundles and self-hosted fonts. Everything the page needs is here;
    # nothing is fetched from a CDN (ADR-0018).
    app.mount(
        "/assets",
        StaticFiles(directory=WEB_DIST / "assets"),
        name="assets",
    )


@app.get("/{full_path:path}", include_in_schema=False)
def serve_console(full_path: str) -> Response:
    """Serve the single-page console, or say plainly that it is not built.

    OPEN, like ``/health``: the console holds no data -- it fetches everything
    through the guarded API -- and it must load to show its sign-in prompt.

    A SPA catch-all that returns index.html for EVERY unmatched path turns a
    mistyped API call into an HTML 200, and the resulting `JSON.parse` failure
    surfaces three frames from the mistake. So anything under an API prefix
    404s here instead.
    """
    head = full_path.split("/", 1)[0]
    if head in API_PREFIXES:
        raise HTTPException(status_code=404, detail=f"no route for /{full_path}")

    index = WEB_DIST / "index.html"
    if not index.is_file():
        # A missing build is an operator error with an exact remedy, so say it
        # rather than 404ing into silence.
        raise HTTPException(
            status_code=503,
            detail=(
                "the console has not been built. Run `make web` (or "
                "`npm --prefix web ci && npm --prefix web run build`) to "
                f"produce {WEB_DIST}."
            ),
        )

    static = WEB_DIST / full_path
    if full_path and static.is_file():
        return FileResponse(static)
    return FileResponse(index)
