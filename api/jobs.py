"""The in-process job runner (ADR-0035).

`POST /scans`, `POST /systems/scan` and `POST /scans/{id}/fix` hand their work
to a small thread pool and answer 202 with a job id. A job's state lives in the
``jobs`` table beside the scans, so `GET /jobs/{id}` reads the store, not this
process's memory -- and a restarted server can see what it interrupted.

**No broker.** Celery or Redis would add a second service to install, secure
and keep alive on an air-gapped host, for a queue that holds a handful of
scans. A thread pool is enough: the heavy part of a scan is its subprocesses
(semgrep, syft), so the GIL is not what limits it.

What that costs, stated rather than hidden:

* **Jobs do not survive the process.** A job queued or running when the server
  stopped is marked failed ("interrupted") at the next start. Nothing resumes
  it; submit it again.
* **One API process per database.** Two servers on one file would each fail
  the other's running jobs at startup.
* **No cancelling a running job.** A thread cannot be stopped safely. A scan
  stores its row in one transaction at the end, so an abandoned one leaves
  nothing half-written.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from core import store
from core.logs import get_logger

__all__ = [
    "DEFAULT_WORKERS",
    "ENV_WORKERS",
    "INTERRUPTED_AT_START",
    "INTERRUPTED_BEFORE_START",
    "JobRunner",
    "describe_failure",
    "execute",
    "worker_count",
]

ENV_WORKERS = "ECDAT_API_WORKERS"
#: Two, so a long system scan does not stop a quick one from starting, and few
#: enough that two semgrep runs do not starve a laptop.
DEFAULT_WORKERS = 2

INTERRUPTED_AT_START = (
    "interrupted: the server stopped before this job finished; submit it again"
)
INTERRUPTED_BEFORE_START = (
    "interrupted: the server shut down before this job started; submit it again"
)

_log = get_logger("api.jobs")

#: A job's work: runs to completion and returns the id of the row it stored.
Work = Callable[[], str]


def worker_count() -> int:
    raw = os.environ.get(ENV_WORKERS, "").strip()
    if not raw:
        return DEFAULT_WORKERS
    try:
        value = int(raw)
    except ValueError:
        value = 0
    if value < 1:
        raise ValueError(f"{ENV_WORKERS} must be a positive integer, got {raw!r}")
    return value


def describe_failure(exc: BaseException) -> str:
    """What a failed job records: the exception's type and its message."""
    return f"{type(exc).__name__}: {exc}"


def execute(job_id: str, work: Work) -> str:
    """Run one job's work, recording every transition. Re-raises on failure.

    The pool AND the synchronous ``?wait=true`` path both come through here,
    so a job cannot be recorded differently depending on how it was run.
    """
    store.mark_job_running(job_id)
    try:
        scan_id = work()
    except Exception as exc:
        reason = describe_failure(exc)
        store.mark_job_failed(job_id, reason)
        _log.warning(
            "job_failed",
            extra={"event": "job_failed", "job_id": job_id, "error": reason},
            exc_info=exc,
        )
        raise
    store.mark_job_done(job_id, scan_id)
    _log.info(
        "job_done", extra={"event": "job_done", "job_id": job_id, "scan_id": scan_id}
    )
    return scan_id


class JobRunner:
    """A fixed pool of worker threads, started and stopped with the app."""

    def __init__(self, workers: int) -> None:
        self.workers = workers
        self._pool = ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="ecdat-job"
        )
        #: Accepted but not yet picked up by a worker.
        self._queued: set[str] = set()
        self._lock = threading.Lock()

    def submit(self, job_id: str, work: Work) -> None:
        with self._lock:
            self._queued.add(job_id)
        self._pool.submit(self._run, job_id, work)

    def _run(self, job_id: str, work: Work) -> None:
        with self._lock:
            self._queued.discard(job_id)
        try:
            execute(job_id, work)
        except Exception:
            # Recorded on the job, and logged, by execute(). A pool thread has
            # no caller to hand the error to.
            return

    def shutdown(self) -> None:
        """Take no more work, fail what never started, wait for what is running.

        Waiting matters: a worker finishing after the app has gone would write
        into whatever database the environment names by then.
        """
        self._pool.shutdown(wait=True, cancel_futures=True)
        with self._lock:
            never_started = sorted(self._queued)
            self._queued.clear()
        for job_id in never_started:
            store.mark_job_failed(job_id, INTERRUPTED_BEFORE_START)
