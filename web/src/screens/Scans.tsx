/**
 * SCANS -- the history, off the denormalised rows (ADR-0016). No CBOM parse.
 *
 * Status is DERIVED from the row with its rule on hover (see `scanStatus`):
 * the store records which scanners were SELECTED, not whether each finished,
 * and it records no start time -- so "Started" says it was not recorded rather
 * than repeating the completion time under a different heading.
 */
import { Plus, RefreshCw } from "lucide-react";
import { useMemo, useState } from "react";

import type { ScanSummary } from "@/api/types";
import { NewScanDialog } from "@/components/NewScanDialog";
import { Button, ScreenHeader, Tag } from "@/components/Panel";
import { EmptyPanel } from "@/components/Honest";
import { cn, formatDateTime } from "@/lib/format";
import { navigate } from "@/lib/router";
import type { ScanView } from "@/state/inventory";
import { scanStatus } from "@/state/metrics";

function driftCell(scan: ScanSummary) {
  const total = Object.values(scan.drift_counts ?? {}).reduce((sum, n) => sum + n, 0);
  // Neutral ink: drift is a finding, not a band, and only bands get colour.
  if (total > 0) return <span className="text-ink">{total}</span>;
  if (scan.coverage_gaps > 0) {
    return (
      <span className="text-ink-faint" title="A view was missing, so no drift could be claimed either way">
        n/a
      </span>
    );
  }
  return <span className="text-ink-faint">0</span>;
}

export function ScansScreen({ view }: { view: ScanView }) {
  const [creating, setCreating] = useState(false);
  const [showDerived, setShowDerived] = useState(false);

  const derivedCount = view.scans.filter((s) => s.kind !== "scan").length;
  const rows = useMemo(
    () => (showDerived ? view.scans : view.scans.filter((s) => s.kind === "scan")),
    [view.scans, showDerived],
  );

  return (
    <div>
      <ScreenHeader
        title="Scans"
        subtitle="Every stored scan, newest first. Rescore and fix passes are linked rows of their parent, never edits of it."
        actions={
          <>
            <Button onClick={() => view.reload()}>
              <RefreshCw className="h-3 w-3" aria-hidden /> Refresh
            </Button>
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus className="h-3 w-3" aria-hidden /> New scan
            </Button>
          </>
        }
      />

      <div className="flex items-center gap-3 border-b border-line bg-panel px-5 py-2 text-2xs">
        <button
          type="button"
          aria-pressed={showDerived}
          onClick={() => setShowDerived((value) => !value)}
          className={cn(
            "border px-2 py-0.5 transition-colors",
            showDerived ? "border-ink-dim bg-raised text-ink" : "border-line text-ink-faint hover:text-ink-dim",
          )}
        >
          Derived rows ({derivedCount})
        </button>
        <span className="text-ink-faint">
          Each Mosca slider move stores a rescore row; they are hidden unless asked for.
        </span>
        <span className="ml-auto font-mono tabular-nums text-ink-faint">{rows.length}</span>
      </div>

      {rows.length === 0 && !view.loading ? (
        <div className="p-4">
          <EmptyPanel title="No scans stored in this database">
            Start one with <strong className="text-ink-dim">New scan</strong>, or run{" "}
            <code className="font-mono">ecdat scan</code> with the same{" "}
            <code className="font-mono">ECDAT_DB</code> the server opened.
          </EmptyPanel>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-xs">
            <thead>
              <tr className="bg-raised text-left text-2xs uppercase tracking-widest text-ink-faint">
                <th className="border-b border-line px-3 py-1.5 font-medium">Name</th>
                <th className="border-b border-line px-3 py-1.5 font-medium">System</th>
                <th className="border-b border-line px-3 py-1.5 font-medium">Started</th>
                <th className="border-b border-line px-3 py-1.5 font-medium">Completed</th>
                <th className="border-b border-line px-3 py-1.5 text-right font-medium">Artefacts</th>
                <th className="border-b border-line px-3 py-1.5 text-right font-medium">Critical</th>
                <th className="border-b border-line px-3 py-1.5 text-right font-medium">High</th>
                <th className="border-b border-line px-3 py-1.5 text-right font-medium">Drift</th>
                <th className="border-b border-line px-3 py-1.5 font-medium">Status</th>
                <th className="border-b border-line px-3 py-1.5" />
              </tr>
            </thead>
            <tbody>
              {rows.map((scan) => {
                const status = scanStatus(scan);
                const current = view.scan?.id === scan.id;
                return (
                  <tr
                    key={scan.id}
                    aria-selected={current}
                    onClick={() => view.selectScan(scan.id)}
                    className={cn(
                      "cursor-pointer border-b border-line-soft border-l-2 transition-colors",
                      current ? "border-l-ink-dim bg-raised" : "border-l-transparent hover:bg-raised/60",
                    )}
                  >
                    <td className="px-3 py-1.5">
                      <div className="flex items-baseline gap-2">
                        <span className="font-medium text-ink">{scan.target.ref}</span>
                        <span className="font-mono text-[10px] text-ink-faint">{scan.id.slice(0, 8)}</span>
                        {scan.kind !== "scan" ? (
                          <Tag title={`derived from ${scan.parent_scan_id ?? "unknown"}`}>
                            {scan.kind} of {scan.parent_scan_id?.slice(0, 8) ?? "?"}
                          </Tag>
                        ) : null}
                      </div>
                      <div className="text-[10px] text-ink-faint">{scan.target.kind}</div>
                    </td>
                    <td className="px-3 py-1.5 text-ink-dim">{scan.target.system ?? "—"}</td>
                    <td className="px-3 py-1.5">
                      <span className="text-ink-faint" title="The store records when a scan was saved, not when it began">
                        not recorded
                      </span>
                    </td>
                    <td className="px-3 py-1.5 font-mono text-[10px] tabular-nums text-ink-dim">
                      {formatDateTime(scan.created_at)}
                    </td>
                    <td className="px-3 py-1.5 text-right font-mono tabular-nums text-ink">{scan.component_count}</td>
                    <td className="px-3 py-1.5 text-right font-mono tabular-nums">
                      <span className={scan.band_counts.Critical ? "text-critical" : "text-ink-faint"}>
                        {scan.band_counts.Critical ?? 0}
                      </span>
                    </td>
                    <td className="px-3 py-1.5 text-right font-mono tabular-nums">
                      <span className={scan.band_counts.High ? "text-high" : "text-ink-faint"}>
                        {scan.band_counts.High ?? 0}
                      </span>
                    </td>
                    <td className="px-3 py-1.5 text-right font-mono tabular-nums">{driftCell(scan)}</td>
                    <td className="px-3 py-1.5">
                      <Tag
                        variant={status.status === "COMPLETE" ? "verified" : status.status === "PARTIAL" ? "provisional" : "plain"}
                        title={status.reason}
                      >
                        {status.status}
                      </Tag>
                    </td>
                    <td className="px-3 py-1.5 text-right">
                      <button
                        type="button"
                        onClick={(event) => {
                          event.stopPropagation();
                          view.selectScan(scan.id);
                          navigate("overview");
                        }}
                        className="text-2xs text-ink-faint hover:text-ink"
                      >
                        Open →
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <NewScanDialog
        open={creating}
        onOpenChange={setCreating}
        onCreated={(scanId) => view.selectScan(scanId)}
      />
    </div>
  );
}
