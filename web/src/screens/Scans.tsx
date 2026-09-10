/**
 * SCANS -- "Scan History", off the denormalised rows (ADR-0016). No CBOM parse.
 *
 * Laid out as web/design/ has it (ADR-0032): the table inside an "execution
 * log" card, with the latest scan's status as a pill. Status is DERIVED from
 * the row with its rule on hover (`scanStatus`); the store records which
 * scanners were OFFERED, not whether each finished, and no start time -- so
 * "Started" says it was not recorded rather than inventing one.
 *
 * The list is read a PAGE at a time (ADR-0035): the screen asks the server for
 * one page and shows its range against the server's total. Paging is the
 * server's -- this screen never slices a list it holds.
 */
import { ChevronLeft, ChevronRight, RefreshCw, ScanLine } from "lucide-react";
import { useState } from "react";

import { listScans } from "@/api/client";
import type { Page, ScanSummary } from "@/api/types";
import { EmptyPanel } from "@/components/Honest";
import { NewScanDialog } from "@/components/NewScanDialog";
import { Button, Panel, Pill, ScreenHeader, Tag } from "@/components/Panel";
import { cn, formatDateTime, pad2 } from "@/lib/format";
import { navigate } from "@/lib/router";
import { canAdmin, NEEDS_ADMIN, useAuth } from "@/state/auth";
import type { ScanView } from "@/state/inventory";
import { scanStatus } from "@/state/metrics";
import { useRemote } from "@/state/remote";

/** Rows per page of Scan History. */
export const SCANS_PAGE_SIZE = 25;

const TH =
  "border-b border-line px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-[0.12em] text-ink-faint";

interface HistoryPage {
  page: Page<ScanSummary>;
  /** Rescore and fix rows in the whole store, for the toggle's label. */
  derived: number;
}

/**
 * One page, plus the OTHER total, so the toggle can say how many derived rows
 * exist without fetching them (a `limit=1` request is a count).
 */
async function loadHistory(showDerived: boolean, offset: number): Promise<HistoryPage> {
  const [page, other] = await Promise.all([
    listScans({ kind: showDerived ? undefined : "scan", limit: SCANS_PAGE_SIZE, offset }),
    listScans({ kind: showDerived ? "scan" : undefined, limit: 1 }),
  ]);
  const everything = showDerived ? page.total : other.total;
  const originals = showDerived ? other.total : page.total;
  return { page, derived: everything - originals };
}

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
  const { principal } = useAuth();
  const admin = canAdmin(principal);
  const [creating, setCreating] = useState(false);
  const [showDerived, setShowDerived] = useState(false);
  const [offset, setOffset] = useState(0);
  const [nonce, setNonce] = useState(0);

  const history = useRemote(`scans:${showDerived}:${offset}:${nonce}`, () => loadHistory(showDerived, offset));
  const page = history.data?.page ?? null;
  const rows = page?.items ?? [];
  const total = page?.total ?? 0;
  // The range comes from the page the SERVER returned, so it can never
  // describe one page while the table still shows another.
  const shownFrom = page?.offset ?? 0;

  const latest = view.scans.find((s) => s.kind === "scan") ?? null;
  const latestStatus = latest ? scanStatus(latest) : null;
  const system = view.scan?.target.system ?? view.scan?.target.ref;

  function refresh() {
    view.reload();
    setNonce((n) => n + 1);
  }

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
          <Button
            variant="primary"
            onClick={() => setCreating(true)}
            disabled={!admin}
            title={admin ? "Scan a target, or a whole system manifest" : NEEDS_ADMIN}
          >
            <ScanLine className="h-3.5 w-3.5" aria-hidden /> New scan
          </Button>
        }
      />

      <div className="px-6 pb-6">
        <Panel
          eyebrow={`Execution log / ${pad2(total)} records`}
          title="Previous scans"
          meta={
            <>
              <Button
                variant="quiet"
                aria-pressed={showDerived}
                onClick={() => {
                  setShowDerived((value) => !value);
                  setOffset(0);
                }}
                title="Each Mosca slider move stores a rescore row; they are hidden unless asked for"
                className={cn("px-2 py-1 text-[11.5px]", showDerived ? "text-ink" : "text-ink-faint")}
              >
                Derived rows ({history.data ? history.data.derived : "…"})
              </Button>
              <Button
                variant="quiet"
                aria-label="Refresh"
                title="Reload the scan list"
                onClick={refresh}
                className="px-2 py-1 text-ink-faint"
              >
                <RefreshCw className="h-3.5 w-3.5" aria-hidden />
              </Button>
              {latestStatus ? <Pill title={latestStatus.reason}>Latest {latestStatus.status.toLowerCase()}</Pill> : null}
            </>
          }
        >
          {history.error ? (
            <EmptyPanel title="Scan history could not be loaded">
              {history.error}. This is a failed request, not an empty database.
            </EmptyPanel>
          ) : total === 0 && !history.loading ? (
            <EmptyPanel title="No scans stored in this database">
              Start one with <strong className="text-ink-dim">New scan</strong>, or run{" "}
              <code className="font-mono">ecdat scan</code> with the same{" "}
              <code className="font-mono">ECDAT_DB</code> the server opened.
            </EmptyPanel>
          ) : (
            <>
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
                          data-testid="scan-row"
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
              <div className="mt-3 flex items-center justify-between gap-3 text-[11.5px] text-ink-faint">
                <span className="font-mono tabular-nums">
                  {rows.length > 0 ? (
                    <>
                      Showing {shownFrom + 1}–{shownFrom + rows.length} of {total}
                    </>
                  ) : (
                    "Loading…"
                  )}
                </span>
                <div className="flex items-center gap-1">
                  <Button
                    variant="quiet"
                    aria-label="Previous page"
                    disabled={history.loading || shownFrom === 0}
                    onClick={() => setOffset(Math.max(0, shownFrom - SCANS_PAGE_SIZE))}
                    className="px-2 py-1"
                  >
                    <ChevronLeft className="h-3.5 w-3.5" aria-hidden />
                  </Button>
                  <Button
                    variant="quiet"
                    aria-label="Next page"
                    disabled={history.loading || shownFrom + rows.length >= total}
                    onClick={() => setOffset(shownFrom + SCANS_PAGE_SIZE)}
                    className="px-2 py-1"
                  >
                    <ChevronRight className="h-3.5 w-3.5" aria-hidden />
                  </Button>
                </div>
              </div>
            </>
          )}
        </Panel>
      </div>

      <NewScanDialog
        open={creating}
        onOpenChange={setCreating}
        onCreated={(scanId) => {
          view.selectScan(scanId);
          setOffset(0);
          setNonce((n) => n + 1);
        }}
      />
    </div>
  );
}
