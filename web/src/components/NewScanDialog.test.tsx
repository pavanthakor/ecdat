/**
 * New scan, as a JOB (ADR-0035): `POST /scans` answers 202 with a job id at
 * once, and the dialog polls `GET /jobs/{id}` until the scan is stored. The
 * scan id is handed over only when the job is DONE -- never the job id in its
 * place -- and a failed job shows the server's reason.
 */
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { Job } from "@/api/types";
import { NewScanDialog } from "./NewScanDialog";

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

function job(status: Job["status"], extra: Partial<Job> = {}): Job {
  return {
    id: "job-7",
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

/** The job answers each state in turn, then repeats the last one. */
function server(states: Job[]) {
  const calls: { url: string; method: string; body: unknown }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      calls.push({ url, method, body: init?.body ? JSON.parse(String(init.body)) : undefined });
      if (url.endsWith("/api/scanners")) return json(["source"]);
      if (url === "/api/scans" && method === "POST") {
        return json({ job_id: "job-7", kind: "scan", status: "pending" }, 202);
      }
      if (url.endsWith("/api/jobs/job-7")) return json(states.length > 1 ? states.shift() : states[0]);
      return json({}, 404);
    }),
  );
  return calls;
}

async function submit() {
  await userEvent.type(screen.getByPlaceholderText("testdata/quantumbank"), "testdata/quantumbank");
  await userEvent.click(screen.getByRole("button", { name: /run scan/i }));
}

afterEach(() => vi.unstubAllGlobals());

describe("NewScanDialog -- a scan is a job", () => {
  it("queues the scan, polls the job, and hands over the SCAN id only when done", async () => {
    const calls = server([job("pending"), job("running"), job("done", { scan_id: "scan-9" })]);
    const onCreated = vi.fn();
    const onOpenChange = vi.fn();
    render(<NewScanDialog open onOpenChange={onOpenChange} onCreated={onCreated} pollMs={1} />);

    await submit();

    await waitFor(() => expect(onCreated).toHaveBeenCalledWith("scan-9"));
    expect(onCreated).toHaveBeenCalledTimes(1);
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(calls.filter((call) => call.url.endsWith("/api/jobs/job-7"))).toHaveLength(3);
    expect(calls.find((call) => call.method === "POST")?.body).toMatchObject({
      kind: "repo",
      ref: "testdata/quantumbank",
    });
  });

  it("while the job runs, the dialog says so and names the job", async () => {
    server([job("running")]);
    render(<NewScanDialog open onOpenChange={vi.fn()} onCreated={vi.fn()} pollMs={1} />);

    await submit();

    const status = await screen.findByTestId("job-status");
    await waitFor(() => expect(status).toHaveAttribute("data-status", "running"));
    expect(status).toHaveTextContent("job-7");
  });

  it("a failed job shows the server's reason and hands over nothing", async () => {
    server([job("failed", { error: "TargetUnreadableError: target 'x.tar' (kind=image) is not a readable file" })]);
    const onCreated = vi.fn();
    render(<NewScanDialog open onOpenChange={vi.fn()} onCreated={onCreated} pollMs={1} />);

    await submit();

    expect(await screen.findByText(/x\.tar/)).toBeInTheDocument();
    expect(onCreated).not.toHaveBeenCalled();
  });
});
