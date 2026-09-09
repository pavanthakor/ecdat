"""The ECDAT HTTP API.

Thin by design: it runs the orchestrator and serves what the store holds. No
scanning logic, no scoring, no reshaping of the CBOM -- the document is handed
back as the exact bytes that were stored, because re-encoding it through a JSON
serialiser would quietly break the determinism guarantee ADR-0002 rests on.
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
from core.orchestrator import default_context, run_scan
from core.scanner import Target
from policy.engine import BANDS

__all__ = ["app"]

_log = get_logger("api")

#: Band names, highest severity first, straight from the policy engine so the
#: API cannot drift from the bands the engine actually assigns.
BAND_NAMES = tuple(band for _threshold, band in BANDS)

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

    kind: Literal["repo", "directory", "image", "host", "endpoint"]
    ref: str = Field(min_length=1)
    system: str | None = None
    data_class: str | None = None
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
    )
    scan_id = run_scan(target, scanners, default_context())
    scan = store.get_scan(scan_id)
    if scan is None:  # pragma: no cover - the row was just committed
        raise HTTPException(status_code=500, detail="scan disappeared after saving")
    return ScanCreated(scan_id=scan.id, component_count=scan.component_count)


def _verdict_summary(cbom_json: str) -> tuple[dict[str, int], int]:
    """Band counts and the top score, read back out of a stored CBOM.

    Parsed from the document rather than recomputed from the packs: the summary
    must report what was stored, not what today's packs would say about it.
    Re-scoring is a deliberate act, not a side effect of listing scans.
    """
    counts = dict.fromkeys(BAND_NAMES, 0)
    top = 0
    for component in json.loads(cbom_json).get("components", []):
        for prop in component.get("properties", []):
            if prop["name"] == "ecdat:band" and prop["value"] in counts:
                counts[prop["value"]] += 1
            elif prop["name"] == "ecdat:score":
                top = max(top, int(prop["value"]))
    return counts, top


@app.get("/scans")
def list_scans() -> list[ScanSummary]:
    summaries = []
    for scan in store.list_scans():
        band_counts, max_score = _verdict_summary(scan.cbom_json)
        summaries.append(
            ScanSummary(
                id=scan.id,
                target=TargetOut(
                    kind=scan.target_kind,
                    ref=scan.target_ref,
                    system=scan.target_system,
                    data_class=scan.target_data_class,
                ),
                created_at=scan.created_at,
                component_count=scan.component_count,
                band_counts=band_counts,
                max_score=max_score,
            )
        )
    return summaries


@app.get("/scans/{scan_id}/cbom")
def get_cbom(scan_id: str) -> Response:
    scan = store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"no scan with id {scan_id!r}")
    # Verbatim bytes: see the module docstring.
    return Response(content=scan.cbom_json, media_type="application/json")
