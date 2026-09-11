/**
 * Re-scan the loaded scan's target -- the same kind, ref, system and scoring
 * context -- as a job (ADR-0035), and follow it to its stored scan.
 *
 * Used where the v2 design offers "Re-scan": after applying a verified patch
 * (Verified Fixes) and after rebuilding what drifted (Cryptographic Drift). A
 * re-scan stores a NEW row; it never edits the scan on screen, so the result is
 * something to select and compare, not a changed history. Leaving the screen
 * stops following the job, not the job.
 */
import { useEffect, useRef, useState } from "react";

import { createScan, waitForJob } from "@/api/client";
import type { Exposure, ScanSummary, Sector, TargetKind } from "@/api/types";
import { Z_DEFAULT } from "@/state/inventory";

export interface RescanState {
  state: "idle" | "running" | "done" | "error";
  message?: string;
}

export function useRescan(scan: ScanSummary | null): { rescan: RescanState; start: () => Promise<void> } {
  const [rescan, setRescan] = useState<RescanState>({ state: "idle" });
  const following = useRef(new Set<AbortController>());
  useEffect(() => {
    const controllers = following.current;
    return () => controllers.forEach((controller) => controller.abort());
  }, []);

  async function start() {
    if (!scan) return;
    const controller = new AbortController();
    following.current.add(controller);
    const { signal } = controller;
    setRescan({ state: "running", message: "Queued a re-scan of the same target…" });
    try {
      const accepted = await createScan({
        kind: scan.target.kind as TargetKind,
        ref: scan.target.ref,
        system: scan.target.system,
        data_class: scan.target.data_class,
        sector: (scan.sector ?? "other") as Sector,
        exposure: (scan.exposure ?? "unknown") as Exposure,
        z_years: scan.z_years ?? Z_DEFAULT,
      });
      const done = await waitForJob(accepted.job_id, {
        signal,
        onUpdate: (job) =>
          setRescan({ state: "running", message: `Re-scan job ${job.id.slice(0, 8)} is ${job.status}…` }),
      });
      setRescan({
        state: "done",
        message: `Stored as scan ${(done.scan_id ?? "?").slice(0, 8)} — select it in Scans, then compare.`,
      });
    } catch (cause) {
      if (signal.aborted) return;
      setRescan({ state: "error", message: cause instanceof Error ? cause.message : String(cause) });
    }
  }

  return { rescan, start };
}
