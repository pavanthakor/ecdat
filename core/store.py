"""Persistence for scans: the CBOM, and enough about the run to repeat it.

The CBOM is stored as the exact text the normaliser produced. It is not parsed
into rows and reassembled -- the whole determinism guarantee is about bytes, and
the only way to keep it is to hand back the same bytes.

A row is **self-describing** (ADR-0016). Alongside the document it records what
ran (``scanners_ran``), in what context (``sector``, ``exposure``, ``z_years``)
and what the verdict was (``band_counts``, ``max_score``, ``drift_counts``,
``coverage_gaps``). Without the first, "was this estate ever scanned for
binaries, or does it just have no binary findings?" is unanswerable and the two
states look identical. Without the second, a later fix pass or rescore has to
re-invent the context, and the defaults it would invent (``other``/``unknown``)
are the PERMISSIVE ones -- so a fix would be judged more leniently than the
scan that found the problem.

**History is append-only.** A fix pass and a rescore write NEW rows carrying
``parent_scan_id`` and a ``kind``; the parent is never amended. Silently
rewriting a stored inventory is worse than not showing fixes at all, and it is
the same refusal the fix engine makes about the filesystem.

MIGRATION: :func:`init_db` adds any missing column with ``ALTER TABLE ... ADD
COLUMN`` after introspecting ``PRAGMA table_info``. Additive only -- nothing is
dropped, renamed or retyped -- so opening a database written by an older ECDAT
gains the columns with no data loss and no Alembic. See ADR-0016 for why not
Alembic (yet), and for the rule that keeps this approach honest.

PORTABILITY: these models are written to run unchanged on PostgreSQL later.
No SQLite-only types, no ``AUTOINCREMENT``, no ``INSERT OR REPLACE``; ids are
application-generated UUID strings, timestamps are timezone-aware, and the CBOM
lives in a plain ``Text`` column. The SQLite-specific parts are the URL built in
:func:`database_url` and the ``PRAGMA``-driven migration, which is confined to
:func:`_add_missing_columns`.
"""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Engine,
    Integer,
    String,
    Text,
    create_engine,
    select,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from core.scanner import Target
from core.summary import summarise

__all__ = [
    "ENV_DB_PATH",
    "KIND_FIX",
    "KIND_RESCORE",
    "KIND_SCAN",
    "Scan",
    "ScannerRecord",
    "StoredContext",
    "children_of",
    "database_path",
    "database_url",
    "get_scan",
    "init_db",
    "latest_child",
    "list_scans",
    "reset_engines",
    "save_fix_result",
    "save_rescore",
    "save_scan",
]

ENV_DB_PATH = "ECDAT_DB"
DEFAULT_DB_PATH = "ecdat.db"

#: What produced a row. A plain string rather than an enum column, so adding a
#: kind later is not a migration.
KIND_SCAN = "scan"
KIND_FIX = "fix"
KIND_RESCORE = "rescore"

#: One entry in ``scanners_ran``: ``{"id": ..., "version": ...}``. ``version``
#: is omitted rather than null when a plugin does not declare one -- an absent
#: key says "this plugin has no version", a null would say "it has one and we
#: lost it".
ScannerRecord = dict[str, str]


@dataclass(frozen=True, slots=True)
class StoredContext:
    """The scoring context recorded on a row, so the run can be repeated.

    Every field is optional because rows written before ADR-0016 genuinely do
    not have one. ``None`` means "not recorded", and callers must treat that as
    unknown rather than as a default -- see :meth:`Scan.context`.
    """

    sector: str | None = None
    exposure: str | None = None
    z_years: int | None = None


class Base(DeclarativeBase):
    pass


class Scan(Base):
    """One completed scan of one target, or one pass derived from another."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    target_ref: Mapped[str] = mapped_column(String(2048), nullable=False)
    target_system: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target_data_class: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    cbom_json: Mapped[str] = mapped_column(Text, nullable=False)
    component_count: Mapped[int] = mapped_column(Integer, nullable=False)

    # -- what ran -------------------------------------------------------
    #: ``[{"id": "config"}, {"id": "source", "version": "1.176.1"}]``.
    #: NULL = UNKNOWN (a row written before this column existed).
    #: ``[]`` = known, and nothing ran (an empty selection, or a rescore).
    #: These two must never be collapsed: one is missing information, the
    #: other IS information.
    scanners_ran: Mapped[list[ScannerRecord] | None] = mapped_column(
        JSON(none_as_null=True), nullable=True
    )

    # -- in what context ------------------------------------------------
    sector: Mapped[str | None] = mapped_column(String(32), nullable=True)
    exposure: Mapped[str | None] = mapped_column(String(32), nullable=True)
    z_years: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # -- what the verdict was (denormalised; see core/summary.py) --------
    band_counts: Mapped[dict[str, int] | None] = mapped_column(
        JSON(none_as_null=True), nullable=True
    )
    max_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    drift_counts: Mapped[dict[str, int] | None] = mapped_column(
        JSON(none_as_null=True), nullable=True
    )
    coverage_gaps: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # -- lineage --------------------------------------------------------
    #: The scan this row was derived from, for ``fix`` and ``rescore`` rows.
    #: Deliberately not a database FOREIGN KEY: SQLite enforces those only with
    #: a per-connection pragma, so declaring one would suggest a guarantee that
    #: is not actually switched on. The link is maintained by this module,
    #: which is the only thing that writes it.
    parent_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    kind: Mapped[str] = mapped_column(
        String(16), nullable=False, default=KIND_SCAN, server_default=KIND_SCAN
    )

    def context(self) -> StoredContext:
        """The scoring context this row recorded, with no defaults applied."""
        return StoredContext(
            sector=self.sector, exposure=self.exposure, z_years=self.z_years
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Scan {self.id} {self.kind} {self.target_kind}:{self.target_ref}>"


# ---------------------------------------------------------------------------
# The additive migration
# ---------------------------------------------------------------------------

#: ``column name -> DDL``, for columns added after the first release. Order is
#: not significant; presence is checked per column, so a database at any
#: intermediate version converges to the current one.
#:
#: EVERY entry here must be nullable, or carry a non-null DEFAULT. SQLite can
#: only add a NOT NULL column when a default is supplied, and more importantly
#: an existing row has no value to put there -- inventing one would be exactly
#: the fabricated history this store refuses to write.
ADDED_COLUMNS: tuple[tuple[str, str], ...] = (
    ("scanners_ran", "JSON"),
    ("sector", "VARCHAR(32)"),
    ("exposure", "VARCHAR(32)"),
    ("z_years", "INTEGER"),
    ("band_counts", "JSON"),
    ("max_score", "INTEGER"),
    ("drift_counts", "JSON"),
    ("coverage_gaps", "INTEGER"),
    ("parent_scan_id", "VARCHAR(36)"),
    ("kind", f"VARCHAR(16) NOT NULL DEFAULT '{KIND_SCAN}'"),
)

# Engines are cached per URL rather than created once at import, so that
# changing ECDAT_DB (tests, or a second database on the CLI) takes effect.
_ENGINES: dict[str, Engine] = {}
_INITIALISED: set[str] = set()


def database_path() -> Path:
    return Path(os.environ.get(ENV_DB_PATH, DEFAULT_DB_PATH))


def database_url() -> str:
    return f"sqlite+pysqlite:///{database_path()}"


def get_engine() -> Engine:
    url = database_url()
    engine = _ENGINES.get(url)
    if engine is None:
        engine = create_engine(url)
        _ENGINES[url] = engine
    return engine


def _existing_columns(engine: Engine) -> set[str]:
    with engine.connect() as connection:
        return {row[1] for row in connection.execute(text("PRAGMA table_info(scans)"))}


def _add_missing_columns(engine: Engine) -> list[str]:
    """Add any column in :data:`ADDED_COLUMNS` the table does not have.

    Introspection-driven rather than version-stamped: there is no schema
    version to get out of step with the file on disk, and running this against
    an already-current database is a no-op rather than an error.
    """
    existing = _existing_columns(engine)
    added = [name for name, _ddl in ADDED_COLUMNS if name not in existing]
    if not added:
        return []

    with engine.begin() as connection:
        for name, ddl in ADDED_COLUMNS:
            if name in existing:
                continue
            # Identifier and type come from the module constant above, never
            # from a caller: this is fixed DDL, not a query built from input.
            connection.execute(text(f"ALTER TABLE scans ADD COLUMN {name} {ddl}"))
    return added


def _backfill_summaries(engine: Engine) -> None:
    """Fill the verdict summary for rows that predate those columns.

    The summary is DERIVABLE from bytes already on the row, so reconstructing
    it is reading, not inventing. The scan CONTEXT is not derivable and is
    deliberately left NULL -- a migration that guessed `sector` would put a
    number in the dashboard that nobody ever measured.

    Runs once: the sentinel is ``band_counts IS NULL``, and a genuinely empty
    CBOM still writes a full zeroed band map.
    """
    with engine.begin() as connection:
        rows = connection.execute(
            text("SELECT id, cbom_json FROM scans WHERE band_counts IS NULL")
        ).all()
        for scan_id, cbom_json in rows:
            try:
                document = json.loads(cbom_json)
            except (json.JSONDecodeError, TypeError):
                # A row we cannot parse keeps its NULLs rather than gaining a
                # zeroed summary that would read as "scanned, nothing found".
                continue
            if not isinstance(document, dict):
                continue
            summary = summarise(document)
            connection.execute(
                text(
                    "UPDATE scans SET band_counts = :bands, max_score = :top, "
                    "drift_counts = :drift, coverage_gaps = :gaps WHERE id = :id"
                ),
                {
                    "bands": json.dumps(summary.band_counts),
                    "top": summary.max_score,
                    "drift": json.dumps(summary.drift_counts),
                    "gaps": summary.coverage_gaps,
                    "id": scan_id,
                },
            )


def init_db() -> None:
    """Create any missing tables, then any missing columns. Idempotent."""
    engine = get_engine()
    Base.metadata.create_all(engine)
    if _add_missing_columns(engine):
        _backfill_summaries(engine)
    _INITIALISED.add(database_url())


def reset_engines() -> None:
    """Drop cached engines. For tests, and for anything that repoints ECDAT_DB."""
    for engine in _ENGINES.values():
        engine.dispose()
    _ENGINES.clear()
    _INITIALISED.clear()


def _ensure_initialised() -> Engine:
    if database_url() not in _INITIALISED:
        init_db()
    return get_engine()


def _as_utc(value: datetime) -> datetime:
    """SQLite gives back naive datetimes; everything stored here is UTC."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _document_of(cbom_json: str) -> dict[str, Any]:
    try:
        document = json.loads(cbom_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"cbom_json is not a JSON document: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError("cbom_json is not a CBOM object")
    return document


def _row(
    *,
    target: Target,
    cbom_json: str,
    scanners_ran: Sequence[ScannerRecord] | None,
    context: StoredContext,
    parent_scan_id: str | None,
    kind: str,
) -> Scan:
    """Build a row, deriving everything derivable from the document itself.

    The summary is computed HERE rather than by the caller, so the columns
    cannot disagree with the bytes beside them: there is one place that writes
    both.
    """
    document = _document_of(cbom_json)
    summary = summarise(document)
    return Scan(
        id=str(uuid.uuid4()),
        target_kind=target.kind,
        target_ref=target.ref,
        target_system=target.system,
        target_data_class=target.data_class,
        created_at=datetime.now(tz=UTC),
        cbom_json=cbom_json,
        component_count=len(document.get("components", [])),
        scanners_ran=None if scanners_ran is None else [dict(e) for e in scanners_ran],
        sector=context.sector,
        exposure=context.exposure,
        z_years=context.z_years,
        band_counts=summary.band_counts,
        max_score=summary.max_score,
        drift_counts=summary.drift_counts,
        coverage_gaps=summary.coverage_gaps,
        parent_scan_id=parent_scan_id,
        kind=kind,
    )


def _persist(scan: Scan) -> str:
    with Session(_ensure_initialised()) as session:
        session.add(scan)
        session.commit()
        return scan.id


def save_scan(
    target: Target,
    cbom_json: str,
    *,
    scanners_ran: Sequence[ScannerRecord] | None = None,
    z_years: int | None = None,
) -> str:
    """Persist a CBOM against its target and return the new scan id.

    ``scanners_ran`` defaults to ``None`` -- UNKNOWN -- rather than to an empty
    list, because a caller that did not say what ran has not told us that
    nothing did. Pass ``[]`` to make that claim explicitly.

    ``sector`` and ``exposure`` come off the target; ``z_years`` is the global
    CRQC horizon the scan was scored against and has no home on the target, so
    it is passed here.
    """
    return _persist(
        _row(
            target=target,
            cbom_json=cbom_json,
            scanners_ran=scanners_ran,
            context=StoredContext(
                sector=target.sector, exposure=target.exposure, z_years=z_years
            ),
            parent_scan_id=None,
            kind=KIND_SCAN,
        )
    )


def _derived(
    parent_scan_id: str,
    cbom_json: str,
    *,
    kind: str,
    scanners_ran: Sequence[ScannerRecord] | None,
    context: StoredContext,
) -> str:
    """Write a row derived from ``parent_scan_id``. The parent is NOT touched.

    The parent is read only to inherit its target. Nothing in this function
    issues an UPDATE, and that is the point: a fix or a rescore adds to the
    history of a scan, it does not revise it.
    """
    parent = get_scan(parent_scan_id)
    if parent is None:
        raise ValueError(f"no scan with id {parent_scan_id!r} to derive from")

    target = Target(
        kind=parent.target_kind,  # type: ignore[arg-type]
        ref=parent.target_ref,
        system=parent.target_system,
        data_class=parent.target_data_class,
    )
    return _persist(
        _row(
            target=target,
            cbom_json=cbom_json,
            scanners_ran=scanners_ran,
            context=context,
            parent_scan_id=parent_scan_id,
            kind=kind,
        )
    )


def save_fix_result(
    parent_scan_id: str,
    fix_cbom_json: str,
    *,
    scanners_ran: Sequence[ScannerRecord] | None = None,
    context: StoredContext | None = None,
) -> str:
    """Persist a fix pass as a NEW row linked to the scan it was run against.

    Never an in-place amend of the parent. See the module docstring.
    """
    return _derived(
        parent_scan_id,
        fix_cbom_json,
        kind=KIND_FIX,
        scanners_ran=scanners_ran,
        context=context or StoredContext(),
    )


def save_rescore(
    parent_scan_id: str,
    cbom_json: str,
    *,
    context: StoredContext | None = None,
) -> str:
    """Persist a re-scoring as a NEW row linked to its parent.

    ``scanners_ran`` is ``[]``, not ``None``: a rescore is precisely the case
    where we know the answer and the answer is "nothing ran".
    """
    return _derived(
        parent_scan_id,
        cbom_json,
        kind=KIND_RESCORE,
        scanners_ran=[],
        context=context or StoredContext(),
    )


def get_scan(scan_id: str) -> Scan | None:
    with Session(_ensure_initialised()) as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return None
        scan.created_at = _as_utc(scan.created_at)
        session.expunge(scan)
        return scan


def list_scans(*, kind: str | None = None) -> list[Scan]:
    """Every row, newest first. The id breaks ties so the order is total.

    Derived rows are listed like any other by default rather than filtered out:
    hiding them would make a fix pass invisible in the one place an operator
    looks for what ECDAT has done. ``kind`` narrows when a caller wants only
    original scans.
    """
    statement = select(Scan).order_by(Scan.created_at.desc(), Scan.id.desc())
    if kind is not None:
        statement = statement.where(Scan.kind == kind)
    with Session(_ensure_initialised()) as session:
        scans = list(session.scalars(statement))
        for scan in scans:
            scan.created_at = _as_utc(scan.created_at)
            session.expunge(scan)
        return scans


def children_of(scan_id: str, *, kind: str | None = None) -> list[Scan]:
    """Rows derived from ``scan_id``, newest first."""
    statement = (
        select(Scan)
        .where(Scan.parent_scan_id == scan_id)
        .order_by(Scan.created_at.desc(), Scan.id.desc())
    )
    if kind is not None:
        statement = statement.where(Scan.kind == kind)
    with Session(_ensure_initialised()) as session:
        scans = list(session.scalars(statement))
        for scan in scans:
            scan.created_at = _as_utc(scan.created_at)
            session.expunge(scan)
        return scans


def latest_child(scan_id: str, *, kind: str) -> Scan | None:
    """The most recent derived row of ``kind``, or ``None``."""
    children = children_of(scan_id, kind=kind)
    return children[0] if children else None
