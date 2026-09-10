/**
 * The client's side of ADR-0035: every request carries the configured key, a
 * 401 asks the console for one, lists come back as pages, and a scan is a job
 * the console polls rather than a request it waits on.
 */
import { waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import scansDoc from "@/test/fixtures/scans.json";

import {
  ApiError,
  createScan,
  fetchBlob,
  getToken,
  JobFailedError,
  listScans,
  onUnauthorized,
  reportPath,
  runFix,
  setToken,
  TOKEN_STORAGE_KEY,
  waitForJob,
  whoami,
} from "./client";
import type { Job } from "./types";

interface Call {
  url: string;
  method: string;
  auth: string | null;
}

function stub(handler: (url: string) => Response) {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push({
        url,
        method: init?.method ?? "GET",
        auth: new Headers(init?.headers).get("Authorization"),
      });
      return handler(url);
    }),
  );
  return calls;
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
const EMPTY_PAGE = { items: [], total: 0, limit: 50, offset: 0 };

function job(status: Job["status"], extra: Partial<Job> = {}): Job {
  return {
    id: "job-1",
    kind: "scan",
    status,
    subject: "repo testdata/quantumbank",
    parent_scan_id: null,
    scan_id: null,
    error: null,
    requested_by: "ops",
    created_at: "2026-09-10T06:00:00Z",
    started_at: null,
    finished_at: null,
    ...extra,
  };
}

beforeEach(() => localStorage.clear());
afterEach(() => {
  vi.unstubAllGlobals();
  localStorage.clear();
});

describe("the configured key rides on every request", () => {
  it("sends Authorization: Bearer <key> once a key is stored", async () => {
    const calls = stub(() => json(EMPTY_PAGE));
    setToken("ecdat_secret-key");

    await listScans();

    expect(localStorage.getItem(TOKEN_STORAGE_KEY)).toBe("ecdat_secret-key");
    expect(calls[0].auth).toBe("Bearer ecdat_secret-key");
  });

  it("sends no Authorization header at all when no key is stored", async () => {
    const calls = stub(() => json(EMPTY_PAGE));

    await listScans();

    expect(calls[0].auth).toBeNull();
  });

  it("forgets the key on sign-out", () => {
    setToken("k");
    setToken(null);

    expect(getToken()).toBeNull();
    expect(localStorage.getItem(TOKEN_STORAGE_KEY)).toBeNull();
  });

  it("a 401 asks the console for a key, passing on the server's own reason", async () => {
    stub(() => json({ detail: "missing credential: send `Authorization: Bearer <api key>`" }, 401));
    const heard: string[] = [];
    const stop = onUnauthorized((detail) => heard.push(detail));

    const failure = await listScans().catch((cause: unknown) => cause);
    stop();

    expect(failure).toBeInstanceOf(ApiError);
    expect((failure as ApiError).status).toBe(401);
    expect(heard).toEqual(["missing credential: send `Authorization: Bearer <api key>`"]);
  });

  it("a 403 is an error with the server's reason -- it does NOT ask for a different key", async () => {
    stub(() => json({ detail: "the key 'auditor' has role 'viewer'; this route needs 'admin'" }, 403));
    const heard: string[] = [];
    const stop = onUnauthorized((detail) => heard.push(detail));

    const failure = (await runFix("scan-1").catch((cause: unknown) => cause)) as ApiError;
    stop();

    expect(failure.status).toBe(403);
    expect(failure.detail).toContain("needs 'admin'");
    expect(failure.message).toContain("needs 'admin'");
    expect(heard).toEqual([]);
  });

  it("whoami(key) checks a CANDIDATE key without storing it or raising the sign-in alarm", async () => {
    const calls = stub(() => json({ detail: "invalid credential" }, 401));
    const heard: string[] = [];
    const stop = onUnauthorized((detail) => heard.push(detail));

    await expect(whoami("wrong-key")).rejects.toBeInstanceOf(ApiError);
    stop();

    expect(calls[0].url).toBe("/api/auth/whoami");
    expect(calls[0].auth).toBe("Bearer wrong-key");
    expect(getToken()).toBeNull();
    expect(heard).toEqual([]);
  });
});

describe("a list is a page", () => {
  it("listScans passes kind, limit and offset, and returns the envelope", async () => {
    const calls = stub(() => json({ items: scansDoc, total: 60, limit: 25, offset: 25 }));

    const page = await listScans({ kind: "scan", limit: 25, offset: 25 });

    expect(calls[0].url).toBe("/api/scans?kind=scan&limit=25&offset=25");
    expect(page.total).toBe(60);
    expect(page.items).toHaveLength(1);
  });

  it("listScans() with no options takes the server's default page", async () => {
    const calls = stub(() => json(EMPTY_PAGE));

    await listScans();

    expect(calls[0].url).toBe("/api/scans");
  });
});

describe("a scan is a job", () => {
  it("createScan returns the ACCEPTED job, not a scan", async () => {
    const calls = stub(() => json({ job_id: "job-1", kind: "scan", status: "pending" }, 202));
    setToken("k");

    const accepted = await createScan({ kind: "repo", ref: "testdata/quantumbank" });

    expect(accepted).toEqual({ job_id: "job-1", kind: "scan", status: "pending" });
    expect(calls[0]).toMatchObject({ url: "/api/scans", method: "POST", auth: "Bearer k" });
  });

  it("waitForJob polls pending -> running -> done and hands back the scan id", async () => {
    const states = [job("pending"), job("running"), job("done", { scan_id: "scan-9" })];
    const calls = stub(() => json(states.shift()));
    const seen: string[] = [];

    const done = await waitForJob("job-1", { intervalMs: 0, onUpdate: (j) => seen.push(j.status) });

    expect(done.scan_id).toBe("scan-9");
    expect(seen).toEqual(["pending", "running", "done"]);
    expect(calls.map((c) => c.url)).toEqual(Array(3).fill("/api/jobs/job-1"));
  });

  it("waitForJob rejects with the job's own reason when it fails", async () => {
    stub(() =>
      json(job("failed", { error: "TargetUnreadableError: target 'x.tar' (kind=image) is not a readable file" })),
    );

    const failure = await waitForJob("job-1", { intervalMs: 0 }).catch((cause: unknown) => cause);

    expect(failure).toBeInstanceOf(JobFailedError);
    expect((failure as JobFailedError).job.status).toBe("failed");
    expect((failure as Error).message).toContain("x.tar");
  });

  it("waitForJob stops polling when aborted", async () => {
    const calls = stub(() => json(job("running")));
    const controller = new AbortController();

    const polling = waitForJob("job-1", { intervalMs: 5, signal: controller.signal });
    await waitFor(() => expect(calls.length).toBeGreaterThan(0));
    controller.abort();

    await expect(polling).rejects.toThrow(/aborted/i);
    const after = calls.length;
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(calls.length).toBe(after);
  });
});

describe("downloads carry the key", () => {
  it("fetchBlob sends Authorization -- which a plain <a href> never could", async () => {
    const calls = stub(() => new Response(new Blob(["%PDF-1.4"], { type: "application/pdf" }), { status: 200 }));
    setToken("k");

    const blob = await fetchBlob(reportPath("scan-1", "executive"));

    expect(calls[0]).toMatchObject({ url: "/api/scans/scan-1/report/executive", auth: "Bearer k" });
    expect(blob.size).toBeGreaterThan(0);
  });
});
