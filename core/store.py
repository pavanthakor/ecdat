"""Persistence for scans: the CBOM and enough about the target to find it again.

The CBOM is stored as the exact text the normaliser produced. It is not parsed
into rows and reassembled -- the whole determinism guarantee is about bytes, and
the only way to keep it is to hand back the same bytes.

PORTABILITY: these models are written to run unchanged on PostgreSQL later.
No SQLite-only types, no ``AUTOINCREMENT``, no ``INSERT OR REPLACE``; ids are
application-generated UUID strings, timestamps are timezone-aware, and the CBOM
lives in a plain ``Text`` column. The only SQLite-specific thing here is the
URL built in :func:`database_url`.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import DateTime, Engine, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from core.scanner import Target

__all__ = [
    "ENV_DB_PATH",
    "Scan",
    "database_path",
    "database_url",
    "get_scan",
    "init_db",
    "list_scans",
    "reset_engines",
    "save_scan",
]

ENV_DB_PATH = "ECDAT_DB"
DEFAULT_DB_PATH = "ecdat.db"


class Base(DeclarativeBase):
    pass


class Scan(Base):
    """One completed scan of one target."""

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

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Scan {self.id} {self.target_kind}:{self.target_ref}>"


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


def init_db() -> None:
    """Create any missing tables. Safe to call repeatedly."""
    Base.metadata.create_all(get_engine())
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


def save_scan(target: Target, cbom_json: str) -> str:
    """Persist a CBOM against its target and return the new scan id."""
    try:
        document = json.loads(cbom_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"cbom_json is not a JSON document: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError("cbom_json is not a CBOM object")

    scan = Scan(
        id=str(uuid.uuid4()),
        target_kind=target.kind,
        target_ref=target.ref,
        target_system=target.system,
        target_data_class=target.data_class,
        created_at=datetime.now(tz=UTC),
        cbom_json=cbom_json,
        component_count=len(document.get("components", [])),
    )
    with Session(_ensure_initialised()) as session:
        session.add(scan)
        session.commit()
        return scan.id


def get_scan(scan_id: str) -> Scan | None:
    with Session(_ensure_initialised()) as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return None
        scan.created_at = _as_utc(scan.created_at)
        session.expunge(scan)
        return scan


def list_scans() -> list[Scan]:
    """Every scan, newest first. The id breaks ties so the order is total."""
    with Session(_ensure_initialised()) as session:
        scans = list(
            session.scalars(
                select(Scan).order_by(Scan.created_at.desc(), Scan.id.desc())
            )
        )
        for scan in scans:
            scan.created_at = _as_utc(scan.created_at)
            session.expunge(scan)
        return scans
