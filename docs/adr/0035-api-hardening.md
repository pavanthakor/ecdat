# ADR-0035: API keys, an in-process job model, and paginated lists

**Status:** Accepted
**Date:** 2026-09-10
**Slice:** API hardening (Tier 3): auth + async jobs + pagination, in one bundle
**Depends on:** ADR-0003 (the scan pipe, and the job model it deferred),
ADR-0016 (the store and its derived rows), ADR-0018 (the console served by
FastAPI), ADR-0019 (system scan), ADR-0020 (reports), ADR-0031/0034 (the
console's candidate filter, revised here)

## Context

Before this slice the API answered anyone who could reach its port. That
included the whole inventory and `GET /scans/{id}/fixes`, which serves verified
patches for an estate's weakest cryptography. `POST /scans`,
`POST /systems/scan` and `POST /scans/{id}/fix` held the request open for the
whole run, which is minutes for a real system scan or fix pass. `GET /scans`
returned every row ever stored, and every Mosca slider settle stores one. The
PUNCHLIST called these three the largest open items.

The constraints come from the problem statement and CLAUDE.md. Everything must
work on an air-gapped host, with no identity provider and no network call. The
secret must be provisioned by configuration and never be a literal in the code
or in the repository. The console has to keep working.

## Decision

### 1. Authentication: API keys as bearer tokens (not JWT)

A key looks like `ecdat_` followed by 43 URL-safe characters: 256 bits from
`secrets.token_urlsafe(32)`. Clients send it as `Authorization: Bearer <key>`.

**Why keys and not JWT.** A JWT's benefit is stateless verification across
services that share a signing key. ECDAT is one process reading one local file,
so that benefit is worth nothing here, and JWT would add:

- a signing secret, which still has to be provisioned;
- expiry and clock handling, which is fragile on a host with no NTP;
- a dependency;
- a revocation problem. A JWT stays valid until it expires unless the server
  keeps a deny-list, and a deny-list is a key file again.

A key is revoked by deleting its entry. The whole mechanism is about 100 lines
of the standard library.

**The secret is configuration, not code.** The server holds only SHA-256
digests. They live in a JSON file named by `ECDAT_API_KEYS`, default
`~/.config/ecdat/api-keys.json` (`$XDG_CONFIG_HOME` is honoured). That is
outside any checkout. The file is written atomically through `mkstemp` (so it
is mode 0600 from its first byte), its directory is 0700, and `.gitignore`
ignores `api-keys*.json` as a second guard. `ecdat api-key create --name
<who> --role viewer|admin` prints the token once, alone on stdout, so
`TOKEN=$(ecdat api-key create ...)` captures it. Nothing can recover a lost
token; it is revoked and a new one issued. `ecdat api-key list` shows names,
roles and digest prefixes, never tokens. `ecdat api-key revoke --name` removes
one.

**Why a plain digest and not bcrypt or argon2.** Those slow hashes exist to
protect passwords people chose. A 256-bit random token has no dictionary to try
against it, so a slow hash would protect nothing and would slow every request.

**The check is local.** Each request reads the file, so a revoke takes effect
on the next request. The presented token is digested and compared against
**every** entry with `hmac.compare_digest`, with no early exit on a match. The
time taken therefore does not reveal which key matched. There is no identity
provider, no network call and no clock.

**Fail closed.**

- No key file means nobody gets in: a 401 that names the remedy.
- A key file that exists but cannot be used (bad JSON, a malformed entry, an
  unknown role) is a 503 for every request. A broken file never degrades into
  "empty", and never into "no auth".
- The startup log names the key file and how many keys it holds, and warns when
  there is no usable key.

### 2. Roles and the route policy

| Route | Guard |
|---|---|
| `GET /health` | open (liveness only) |
| the console's static files (the SPA catch-all) | open: it holds no data and must load to show its sign-in |
| `GET /auth/whoami` | viewer |
| `GET /scans`, `/scans/{id}`, `/scans/{id}/cbom`, `/scans/{a}/compare/{b}`, `/scans/{id}/report/{kind}`, `/scanners`, `/jobs`, `/jobs/{id}` | viewer |
| `POST /scans/{id}/rescore` | viewer (see below) |
| `POST /scans`, `POST /systems/scan`, `POST /scans/{id}/fix` | **admin** |
| `GET /scans/{id}/fixes` | **admin** |

The two roles are ordered. `admin` can do everything `viewer` can.

- **401** means no credential, a malformed one, or a key nobody issued. It
  carries `WWW-Authenticate: Bearer` and a body that says which of those it was.
- **403** means a real key whose role is not enough. The body names the key,
  its role, and the role the route needs:
  `forbidden: the key 'auditor' has role 'viewer'; this route needs 'admin'.`

**Admin routes.** Triggering a scan or a fix pass makes the server read a
target, which is the one thing that reaches beyond the database. The fixes
endpoint is admin as well: a verified patch is a working change to the weakest
crypto in the estate, the most sensitive thing this API serves.

**Rescore is a viewer route, on purpose.** It runs no scanner and reads no
target. It re-scores bytes already stored, and it is the console's Mosca
slider; a viewer who cannot move the slider has half a console. It does write a
derived row (ADR-0016), which is history and never an edit. A viewer can
therefore add rescore rows. That is recorded in the PUNCHLIST.

**Enforcement is structural.** Every route declares exactly one guard.
`tests/test_api_auth.py` reads each route's own dependencies and fails if a
route declares none, or if the admin set differs from the table above, so a
route added tomorrow without a guard cannot pass. FastAPI 0.141 mounts an
included router as a wrapper instead of copying its routes into `app.routes`.
The test therefore reads the shared router directly. One set of route objects
serves both the bare mount and `/api`, and a behavioural test holds the two to
the same answers.

`/docs` and `/openapi.json` stay open. They describe the surface and hold no
data (PUNCHLIST).

### 3. Jobs: in-process, a table and a thread pool

- **A `jobs` table beside `scans`.** It records the kind (`scan`,
  `system-scan`, `fix`), status, subject, parent scan, the scan it stored, the
  error, the NAME of the key that asked, and created/started/finished times.
  `create_all` adds the table to an older database, so no column migration is
  needed. A job is not a scan: a failed job has no scan row, and the append-only
  history gains no placeholder rows.
- **`JobRunner`** is a `ThreadPoolExecutor` sized by `ECDAT_API_WORKERS`
  (default 2). The app's lifespan creates it and shuts it down. Shutdown cancels
  queued jobs and marks them failed ("interrupted before it started"), then
  **waits** for running ones. A worker therefore never writes after the app has
  gone, or, in a test, after the test's database has.
- **A startup sweep.** A job still pending or running when a new process starts
  was interrupted. It is marked failed and says so; it never shows "running"
  forever.
- **Refused now, failed later.** The request is validated before anything is
  queued: the schema, scanner ids, the manifest, the parent row's existence and
  its target kind. A bad request is still a 400 or 404 at once, and no job row
  is written. Reading the target is the job's work, so an unreadable image fails
  the job, with a reason that names the image.
- **The answer** is 202 with `{job_id, kind, status}` and a `Location:
  /jobs/{id}` header. `GET /jobs/{id}` reports pending, running, done (with
  `scan_id`) or failed (with `error`, the exception's type and message).
- **`?wait=true` keeps the synchronous path.** It runs the same `execute()`
  inside the request and answers 201 with the scan and its job id. The
  operator's own mistakes (an unreadable target, an unknown target kind) keep
  the 400 they had before; any other failure is a 500 carrying the reason the
  job records. The CLI stays synchronous and writes no job rows.
- **State changes are conditional.** A job only moves pending → running →
  done or failed. Nothing revives a finished job, and a failure recorded by the
  sweep or by shutdown cannot be overwritten.

**Why no broker.** Celery, Redis or RQ would be a second service to install,
secure and supervise on an air-gapped host, for a queue that holds a handful of
scans. The heavy part of a scan runs in subprocesses (semgrep, syft), so the
GIL does not limit it and threads are enough.

### 4. Pagination

- `GET /scans` and `GET /jobs` answer `{"items", "total", "limit", "offset"}`.
  The default page is 50 rows and the maximum 500. A limit below 1 or above 500,
  or a negative offset, is a 422. `total` counts the rows the filter matches,
  so `GET /scans?kind=scan` counts only scans.
- **The order is total:** newest first, with the id breaking ties. Without a
  total order a row could land on two pages, or on none.
- **Not paginated, by design:** `/scanners` (a fixed registry),
  `/scans/{id}/fixes` (one document's fix results) and compare (two documents).
  None of these can grow with use.
- **Offset, not cursor.** The history is append-only, so the only way a page
  shifts is a new row arriving while someone pages through it, and then by one
  row. That is acceptable for a history screen (PUNCHLIST).

### 5. The console

- **The key.** The console keeps it in localStorage (`ecdat.apiKey`) and sends
  it on every request.
  - Any 401 raises the **sign-in gate**, which shows the server's reason. The
    console never guesses the server's configuration.
  - A key is checked with `GET /auth/whoami` before it is stored, so a refused
    key is never kept.
  - A stored key is checked before the console renders, so a viewer never sees
    an admin control.
  - The user menu shows the key's name and role. "Sign out" forgets the key in
    this browser; the key itself stays valid until revoked on the server.
- **Viewers.** "New scan" is disabled and its title says it needs an admin key.
  The Fixes screen and the drawer say fixes need an admin key, and do not ask
  for them.
- **Jobs.** The New scan dialog and the Fixes screen poll `GET /jobs/{id}`
  every second.
  - They show the state as queued or running, and hand on the scan id only
    when the job is done.
  - A failed job shows the server's reason.
  - Closing the dialog stops the polling, not the job.
- **Downloads.** A link cannot send a header, so the PDFs and the CBOM are
  fetched with the key into a Blob. "View" opens its tab inside the click, where
  a popup blocker allows it, and then points the tab at the Blob.
- **Scan History** asks the server for 25 rows a page and shows "Showing a–b of
  N". The derived-rows count comes from a `limit=1` count request. The shared
  scan view loads the newest page (50 rows). A scan chosen from an older page
  is fetched by id rather than silently replaced by the newest.
- **Still offline:** same-origin only, no identity provider, no CDN.

### 6. Carried over: the "Confirmed" filter (the ADR-0031/0034 addendum)

"Confirmed" now means every row that is NOT flagged a candidate. It used to
mean exactly 1.0. Inferred 0.6 and 0.9 findings, and rows with no recorded
confidence, now appear under "Confirmed". The two toggles partition the table,
and the drawer still gives every row its confidence and the reason for it. On
the captured scans:

- the JS fixture: 1 candidate, 36 confirmed (it was 31, with 5 rows in neither
  toggle);
- the binary scan: 0 candidates, 22 confirmed (it was 0).

## Alternatives considered

- **JWT.** Rejected; see §1.
- **Session cookies and a login form.** These need accounts and passwords, and
  a cookie on a same-origin console brings CSRF with it. Cookies would make
  plain download links work, which does not outweigh either cost.
- **mTLS.** The strongest option, but it means a certificate per operator.
  That is heavier than this tool's threat model needs, and it can be added with
  a reverse proxy without changing ECDAT.
- **FastAPI `BackgroundTasks`.** These run after the response inside the same
  request task, with no concurrency limit, no status table and no answer to a
  restart.
- **Cursor pagination.** Better for a feed that changes under the reader. Offset
  is enough for an append-only history.

## Consequences

- Every client now sends a key. An operator runs `ecdat api-key create` once
  before `make serve`, and the console asks for the key.
- Tests: `tests/conftest.py` points `ECDAT_API_KEYS` at a per-test path, so no
  test can read the developer's real keys. The `api_keys` fixture issues
  `test-viewer` and `test-admin` the same way the CLI does.
- **Limits, all in the PUNCHLIST:**
  - **No TLS of its own.** A bearer key crossing a network needs TLS, so serve
    on localhost or behind a TLS-terminating proxy.
  - **Keys have no expiry and no rotation schedule.**
  - **No rate limit or lockout** on failed attempts.
  - **The audit trail is thin:** a job's `requested_by`, and log lines.
  - **Jobs do not survive a restart.** They are marked failed, not resumed.
  - **One API process per database.** The startup sweep would fail another
    process's running jobs.
  - **A viewer can add rescore rows.**
  - **The console's key sits in localStorage.** Any script on the origin can
    read it. There are no third-party scripts, but there is no CSP header yet.
  - **`/docs` is open.**
  - **Offset pages shift by one** when a row arrives mid-browse.
  - **The top bar and Compare offer only the newest 50 rows.** Older rows are
    reached through Scan History.

## Verification

- `tests/test_api_auth.py` (35 tests) covers:
  - 401 with no token, a malformed token and a wrong token;
  - 403 for a viewer on every admin route, with the admin allowed;
  - a viewer can read and rescore;
  - `/health` is open;
  - the structural guard walk;
  - fail-closed configuration;
  - no source literal or usual default authenticates against an empty key
    file;
  - no key file is tracked, and `.gitignore` covers them;
  - the default key path is outside the repository;
  - the key file holds a digest, at mode 0600;
  - no network call during authentication;
  - one constant-time comparison per issued key;
  - the CLI's create, list and revoke.
- `tests/test_api_jobs.py` (15 tests) covers:
  - 202 plus a job id while the scan is held behind a gate, answering in under
    a second;
  - the job going running → done with its `scan_id`;
  - pending while every worker is busy;
  - system-scan and fix jobs;
  - a patched failure, and a real unreadable-target failure, each failed with
    its reason;
  - refused now, not queued;
  - the restart sweep;
  - `?wait=true` in all three shapes;
  - the viewer's view of a job;
  - no broker in the requirements.
- `tests/test_api_pagination.py` (11 tests) covers `limit` with `total`, offset
  paging with no overlap and no gap, the default page, the bounds, kind-scoped
  totals, and `/jobs`.
- The web tests are `api/client.test.ts`, `state/auth.test.tsx`,
  `components/NewScanDialog.test.tsx` and `screens/scans.test.tsx`, plus the
  certainty tests for §6.
