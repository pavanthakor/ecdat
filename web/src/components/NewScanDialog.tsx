/**
 * Start a scan from the console: one target (`POST /scans`) or a whole system
 * manifest (`POST /systems/scan`, ADR-0019).
 *
 * Both answer at once with a JOB (ADR-0035), and the dialog polls
 * `GET /jobs/{id}`, saying where the job is -- queued, running -- rather than
 * showing a progress bar it has no progress to fill. The scan id is handed on
 * only when the job is DONE; a failed job shows the server's reason. Closing
 * the dialog stops the polling, not the job: the scan still lands in Scans.
 */
import { useEffect, useRef, useState, type FormEvent } from "react";

import { createScan, createSystemScan, JOB_POLL_MS, listScanners, waitForJob } from "@/api/client";
import type { Exposure, JobStatus, Sector, TargetKind } from "@/api/types";
import { cn } from "@/lib/format";
import { Z_DEFAULT } from "@/state/inventory";
import { useRemote } from "@/state/remote";
import { Button } from "./Panel";
import { Modal } from "./ui/dialog";

const KINDS: TargetKind[] = ["repo", "directory", "image", "host", "endpoint", "spool"];
const SECTORS: Sector[] = ["bfsi", "government", "strategic", "defence", "power", "telecom", "transport", "other"];
const EXPOSURES: Exposure[] = ["internet", "internal", "build", "unknown"];

const field =
  "h-8 w-full rounded-md border border-line bg-ground px-2.5 text-[13px] text-ink placeholder:text-ink-faint focus:border-ink-faint focus:outline-none";

function Field({ label, children, hint }: { label: string; children: React.ReactNode; hint?: string }) {
  return (
    <label className="block">
      <span className="eyebrow">{label}</span>
      <div className="mt-1">{children}</div>
      {hint ? <span className="mt-0.5 block text-[10px] text-ink-faint">{hint}</span> : null}
    </label>
  );
}

function jobLine(id: string, status: JobStatus): string {
  const job = `job ${id.slice(0, 8)}`;
  switch (status) {
    case "pending":
      return `Queued as ${job}, waiting for a worker.`;
    case "running":
      return `Running as ${job}. The scan is stored when it finishes.`;
    case "done":
      return `Done: ${job} stored its scan.`;
    default:
      return `Failed: ${job}.`;
  }
}

export function NewScanDialog({
  open,
  onOpenChange,
  onCreated,
  pollMs = JOB_POLL_MS,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: (scanId: string) => void;
  /** How often to ask after the job. */
  pollMs?: number;
}) {
  const [mode, setMode] = useState<"target" | "system">("target");
  const [kind, setKind] = useState<TargetKind>("repo");
  const [ref, setRef] = useState("");
  const [system, setSystem] = useState("");
  const [targets, setTargets] = useState("repo testdata/quantumbank");
  const [dataClass, setDataClass] = useState("");
  const [sector, setSector] = useState<Sector>("other");
  const [exposure, setExposure] = useState<Exposure>("unknown");
  const [zYears, setZYears] = useState(Z_DEFAULT);
  const [excluded, setExcluded] = useState<string[]>([]);
  const [running, setRunning] = useState(false);
  const [job, setJob] = useState<{ id: string; status: JobStatus } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const polling = useRef<AbortController | null>(null);

  const scanners = useRemote(open ? "scanners" : null, listScanners);

  useEffect(() => () => polling.current?.abort(), []);

  function changeOpen(next: boolean) {
    if (!next && polling.current) {
      // Stop following; the job itself carries on and lands in Scans.
      polling.current.abort();
      polling.current = null;
      setRunning(false);
    }
    onOpenChange(next);
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    polling.current?.abort();
    const controller = new AbortController();
    polling.current = controller;
    setRunning(true);
    setError(null);
    setJob(null);
    try {
      const accepted =
        mode === "target"
          ? await createScan({
              kind,
              ref: ref.trim(),
              system: system.trim() || null,
              data_class: dataClass.trim() || null,
              sector,
              exposure,
              z_years: zYears,
              // Omitted = every registered scanner. Only an explicit
              // de-selection sends a list, and then it is honoured exactly.
              scanners:
                excluded.length > 0 && scanners.data
                  ? scanners.data.filter((id) => !excluded.includes(id))
                  : undefined,
            })
          : await createSystemScan({
              system: system.trim(),
              targets: targets
                .split("\n")
                .map((line) => line.trim())
                .filter(Boolean)
                .map((line) => {
                  const [targetKind = "", ...rest] = line.split(/\s+/);
                  return { kind: targetKind, ref: rest.join(" ") };
                }),
              sector,
              exposure,
              data_class: dataClass.trim() || null,
              z_years: zYears,
            });
      setJob({ id: accepted.job_id, status: accepted.status });
      const done = await waitForJob(accepted.job_id, {
        intervalMs: pollMs,
        signal: controller.signal,
        onUpdate: (update) => setJob({ id: update.id, status: update.status }),
      });
      if (!done.scan_id) throw new Error(`job ${done.id} finished without a scan id`);
      onCreated(done.scan_id);
      onOpenChange(false);
    } catch (cause) {
      if (controller.signal.aborted) return; // closed or unmounted: nobody to tell
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      if (!controller.signal.aborted) setRunning(false);
    }
  }

  return (
    <Modal
      open={open}
      onOpenChange={changeOpen}
      title="New scan"
      description="Runs on the server against its filesystem; the console never reads your repo itself."
    >
      <div className="mb-3 flex gap-1" role="tablist">
        {(["target", "system"] as const).map((value) => (
          <button
            key={value}
            type="button"
            role="tab"
            aria-selected={mode === value}
            onClick={() => setMode(value)}
            className={cn(
              "rounded-md border px-3 py-1 text-[12px]",
              mode === value ? "border-ink-dim bg-raised text-ink" : "border-line text-ink-faint hover:text-ink-dim",
            )}
          >
            {value === "target" ? "Single target" : "System manifest"}
          </button>
        ))}
      </div>

      <form onSubmit={submit} className="space-y-3">
        {mode === "target" ? (
          <div className="grid grid-cols-[8rem_1fr] gap-3">
            <Field label="Kind">
              <select className={field} value={kind} onChange={(e) => setKind(e.target.value as TargetKind)}>
                {KINDS.map((k) => (
                  <option key={k}>{k}</option>
                ))}
              </select>
            </Field>
            <Field label="Reference" hint="A path on the SERVER, an image tar, or a spool directory.">
              <input
                required
                className={cn(field, "font-mono")}
                value={ref}
                onChange={(e) => setRef(e.target.value)}
                placeholder="testdata/quantumbank"
              />
            </Field>
          </div>
        ) : (
          <Field label="Targets" hint="One per line: kind then reference — e.g. `image quantumbank.tar`.">
            <textarea
              required
              rows={4}
              className={cn(field, "h-auto py-1.5 font-mono")}
              value={targets}
              onChange={(e) => setTargets(e.target.value)}
            />
          </Field>
        )}

        <div className="grid grid-cols-2 gap-3">
          <Field label="System">
            <input
              required={mode === "system"}
              className={field}
              value={system}
              onChange={(e) => setSystem(e.target.value)}
              placeholder="quantumbank"
            />
          </Field>
          <Field label="Data class">
            <input className={field} value={dataClass} onChange={(e) => setDataClass(e.target.value)} placeholder="pii" />
          </Field>
          <Field label="Sector">
            <select className={field} value={sector} onChange={(e) => setSector(e.target.value as Sector)}>
              {SECTORS.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </Field>
          <Field label="Exposure">
            <select className={field} value={exposure} onChange={(e) => setExposure(e.target.value as Exposure)}>
              {EXPOSURES.map((x) => (
                <option key={x}>{x}</option>
              ))}
            </select>
          </Field>
          <Field label="CRQC horizon (years)">
            <input
              type="number"
              min={0}
              max={100}
              className={cn(field, "font-mono")}
              value={zYears}
              onChange={(e) => setZYears(Number.parseInt(e.target.value, 10) || 0)}
            />
          </Field>
        </div>

        {mode === "target" ? (
          <div>
            <span className="eyebrow">Scanners</span>
            {scanners.error ? (
              <p className="mt-1 text-2xs text-ink-faint">
                The server's scanner list could not be loaded; every registered scanner will run.
              </p>
            ) : (
              <div className="mt-1 flex flex-wrap gap-1.5">
                {(scanners.data ?? []).map((id) => {
                  const on = !excluded.includes(id);
                  return (
                    <button
                      key={id}
                      type="button"
                      aria-pressed={on}
                      onClick={() => setExcluded((list) => (on ? [...list, id] : list.filter((x) => x !== id)))}
                      className={cn(
                        "border px-2 py-0.5 font-mono text-2xs",
                        on ? "border-ink-dim bg-raised text-ink" : "border-dashed border-line text-ink-faint",
                      )}
                    >
                      {id}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        ) : null}

        {job ? (
          <p
            data-testid="job-status"
            data-status={job.status}
            className="border border-line px-2 py-1.5 font-mono text-2xs text-ink-dim"
          >
            {jobLine(job.id, job.status)}
          </p>
        ) : null}

        {error ? <p className="border border-critical/40 bg-critical/10 px-2 py-1.5 text-2xs text-critical">{error}</p> : null}

        <div className="flex items-center justify-between gap-3 border-t border-line pt-3">
          <span className="text-[10px] text-ink-faint">
            {running
              ? "The server runs the scan as a job; closing this stops following it, not the scan."
              : "Queued as a job on the server; this dialog follows it until the scan is stored."}
          </span>
          <Button type="submit" variant="primary" disabled={running}>
            {running ? "Scanning…" : "Run scan"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
