/**
 * SCANS -- "Scan History", off the denormalised rows (ADR-0016). No CBOM parse.
 *
 * Laid out as web/design/ has it (ADR-0032): the table inside an "execution
 * log" card, with the latest scan's status as a pill. Status is DERIVED from
 * the row with its rule on hover (`scanStatus`); the store records which
 * scanners were OFFERED, not whether each finished, and no start time -- so
 * "Started" says it was not recorded rather than inventing one.
 */
import { ChevronRight, RefreshCw, ScanLine } from "lucide-react";
import { useMemo, useState } from "react";

import type { ScanSummary } from "@/api/types";
import { EmptyPanel } from "@/components/Honest";
import { NewScanDialog } from "@/components/NewScanDialog";
import { Button, Panel, Pill, ScreenHeader, Tag } from "@/components/Panel";
import { cn, formatDateTime, pad2 } from "@/lib/format";
import { navigate } from "@/lib/router";
import type { ScanView } from "@/state/inventory";
import { scanStatus } from "@/state/metrics";

const TH =
  "border-b border-line px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-[0.12em] text-ink-faint";

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
  const latest = view.scans.find((s) => s.kind === "scan") ?? null;
  const latestStatus = latest ? scanStatus(latest) : null;
  const system = view.scan?.target.system ?? view.scan?.target.ref;

  return (
    <div>
      <ScreenHeader
        title="Scan History"
        subtitle={
          system
            ? `Security scan executions across ${system}. Rescore and fix passes are linked rows of their parent, never edits of it.`
            : "Security scan executions stored in this database."
        }
        actions={
          <Button variant="primary" onClick={() => setCreating(true)}>
            <ScanLine className="h-3.5 w-3.5" aria-hidden /> New scan
          </Button>
        }
      />

      <div className="px-6 pb-6">
        <Panel
          eyebrow={`Execution log / ${pad2(rows.length)} records`}
          title="Previous scans"
          meta={
            <>
              <Button
                variant="quiet"
                aria-pressed={showDerived}
                onClick={() => setShowDerived((value) => !value)}
                title="Each Mosca slider move stores a rescore row; they are hidden unless asked for"
                className={cn("px-2 py-1 text-[11.5px]", showDerived ? "text-ink" : "text-ink-faint")}
              >
                Derived rows ({derivedCount})
              </Button>
              <Button
                variant="quiet"
                aria-label="Refresh"
                title="Reload the scan list"
                onClick={() => view.reload()}
                className="px-2 py-1 text-ink-faint"
              >
                <RefreshCw className="h-3.5 w-3.5" aria-hidden />
              </Button>
              {latestStatus ? <Pill title={latestStatus.reason}>Latest {latestStatus.status.toLowerCase()}</Pill> : null}
            </>
          }
        >
          {rows.length === 0 && !view.loading ? (
            <EmptyPanel title="No scans stored in this database">
              Start one with <strong className="text-ink-dim">New scan</strong>, or run{" "}
              <code className="font-mono">ecdat scan</code> with the same{" "}
              <code className="font-mono">ECDAT_DB</code> the server opened.
            </EmptyPanel>
          ) : (
            <div className="overflow-x-auto rounded-md border border-line">
              <table className="w-full border-collapse text-[13px]">
                <thead className="bg-raised/60">
                  <tr>
                    <th className={TH}>Scan</th>
                    <th className={TH}>System</th>
                    <th className={TH}>Started</th>
                    <th className={TH}>Completed</th>
                    <th className={TH}>Artefacts</th>
                    <th className={TH}>Critical</th>
                    <th className={TH}>High</th>
                    <th className={TH}>Drift</th>
                    <th className={TH}>Status</th>
                    <th className={TH}>
                      <span className="sr-only">Open</span>
                    </th>
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
                          "cursor-pointer border-b border-line-soft transition-colors last:border-b-0",
                          current ? "bg-raised" : "hover:bg-raised/50",
                        )}
                      >
                        <td className="px-4 py-3.5">
                          <div className="font-semibold text-ink">{scan.target.ref}</div>
                          <div className="mt-0.5 flex items-center gap-2 font-mono text-[11px] text-ink-faint">
                            {scan.id.slice(0, 8)} · {scan.target.kind}
                            {scan.kind !== "scan" ? (
                              <Tag title={`derived from ${scan.parent_scan_id ?? "unknown"}`}>
                                {scan.kind} of {scan.parent_scan_id?.slice(0, 8) ?? "?"}
                              </Tag>
                            ) : null}
                          </div>
                        </td>
                        <td className="px-4 py-3.5 text-ink-dim">{scan.target.system ?? "—"}</td>
                        <td
                          className="px-4 py-3.5 font-mono text-[11.5px] text-ink-faint"
                          title="The store records when a scan was saved, not when it began"
                        >
                          not recorded
                        </td>
                        <td className="px-4 py-3.5 font-mono text-[11.5px] tabular-nums text-ink-dim" title="UTC">
                          {formatDateTime(scan.created_at)}
                        </td>
                        <td className="px-4 py-3.5 font-mono tabular-nums text-ink">{scan.component_count}</td>
                        <td className="px-4 py-3.5 tabular-nums text-ink-dim">{scan.band_counts.Critical ?? 0}</td>
                        <td className="px-4 py-3.5 tabular-nums text-ink-dim">{scan.band_counts.High ?? 0}</td>
                        <td className="px-4 py-3.5 tabular-nums">{driftCell(scan)}</td>
                        <td className="px-4 py-3.5">
                          <Tag
                            variant={
                              status.status === "COMPLETE"
                                ? "verified"
                                : status.status === "PARTIAL"
                                  ? "provisional"
                                  : "plain"
                            }
                            title={status.reason}
                          >
                            {status.status}
                          </Tag>
                        </td>
                        <td className="px-4 py-3.5 text-right">
                          <button
                            type="button"
                            onClick={(event) => {
                              event.stopPropagation();
                              view.selectScan(scan.id);
                              navigate("overview");
                            }}
                            className="inline-flex items-center gap-1 text-[12px] text-ink-dim transition-colors hover:text-ink"
                          >
                            View <ChevronRight className="h-3.5 w-3.5" aria-hidden />
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>

      <NewScanDialog
        open={creating}
        onOpenChange={setCreating}
        onCreated={(scanId) => view.selectScan(scanId)}
      />
    </div>
  );
}
