/**
 * SCANS -- "Scan History", rebuilt on the v2 mockup (scans.html; ADR-0039):
 * four stat cards, the scan timeline, then the history table. Off the
 * denormalised rows (ADR-0016); no CBOM parse.
 *
 * Status is DERIVED from the row with its rule on hover (`scanStatus`); the
 * store records which scanners were OFFERED, not whether each finished, and
 * no start time -- so "Started" says it was not recorded and the mockup's
 * "Avg. duration" is not computed. A failed job stores no row, so failures
 * cannot be counted; "Partial / unknown" counts the rows on this page whose
 * status is not COMPLETE, and says it is this page.
 *
 * The list is read a PAGE at a time (ADR-0035): the screen asks the server for
 * one page and shows its range against the server's total. Paging is the
 * server's -- this screen never slices a list it holds. Run scan is in the
 * topline, as on every v2 screen; a new scan becomes the loaded one and the
 * list picks it up.
 */
import { AlertTriangle, CheckCircle2, ChevronLeft, ChevronRight, Clock, Layers, RefreshCw } from "lucide-react";
import { useState } from "react";

import { listScans } from "@/api/client";
import type { Band, Page, ScanSummary } from "@/api/types";
import { MetricCard } from "@/components/Honest";
import { ScreenHeader } from "@/components/Panel";
import { EmptyState, PanelHead, Prov, tone } from "@/components/v2";
import { cn, formatDate, formatDateTime, pad2 } from "@/lib/format";
import { navigate } from "@/lib/router";
import type { ScanView } from "@/state/inventory";
import { computed, notComputed, scanStatus } from "@/state/metrics";
import { useRemote } from "@/state/remote";

/** Rows per page of Scan History. */
export const SCANS_PAGE_SIZE = 25;

interface HistoryPage {
  page: Page<ScanSummary>;
  /** Original scans in the whole store. */
  originals: number;
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
  return { page, originals, derived: everything - originals };
}

function driftCell(scan: ScanSummary) {
  const total = Object.values(scan.drift_counts ?? {}).reduce((sum, n) => sum + n, 0);
  // Neutral ink: drift is a finding, not a band, and only bands get colour.
  if (total > 0) return <span className="text-ink">{pad2(total)}</span>;
  if (scan.coverage_gaps > 0) {
    return (
      <span className="text-ink-faint" title="A view was missing, so no drift could be claimed either way">
        n/a
      </span>
    );
  }
  return <span className="text-ink-faint">0</span>;
}

/** A band count, in the band's colour when there is one to count. */
function BandCount({ band, n }: { band: Band; n: number }) {
  return n > 0 ? (
    <span data-band={band} className={`band-fg-${tone(band)}`}>
      {pad2(n)}
    </span>
  ) : (
    <span className="text-ink-faint">0</span>
  );
}

function Timeline({ view }: { view: ScanView }) {
  const scan = view.scan;
  const points = scan
    ? view.scans
        .filter(
          (row) =>
            row.kind === "scan" && row.target.ref === scan.target.ref && row.target.system === scan.target.system,
        )
        .sort((a, b) => a.created_at.localeCompare(b.created_at))
        .slice(-7)
    : [];
  const target = scan?.target.system ?? scan?.target.ref;
  return (
    <section className="panel in mb-3" data-testid="scan-timeline" style={{ animationDelay: "0.08s" }}>
      <PanelHead
        title="Scan timeline"
        sub={
          scan
            ? `${points.length} stored scan${points.length === 1 ? "" : "s"} of ${target} · click one to load it`
            : "No scan loaded"
        }
      />
      {points.length === 0 ? (
        <div className="empty-inline">
          <p className="empty-title">No stored scan of this target on the loaded page</p>
        </div>
      ) : (
        <div className="scan-timeline">
          {points.map((point) => {
            const current = point.id === scan?.id;
            return (
              <button
                type="button"
                key={point.id}
                data-testid="timeline-node"
                className={cn("scan-node", current && "current")}
                aria-current={current ? "true" : undefined}
                aria-label={`Load scan ${point.id.slice(0, 8)} from ${formatDate(point.created_at)}`}
                onClick={() => view.selectScan(point.id)}
              >
                <span className="sn-dot" />
                <span className="sn-label">{current ? "Current" : formatDate(point.created_at)}</span>
                <span className="sn-sub">{point.id.slice(0, 8)}</span>
              </button>
            );
          })}
        </div>
      )}
    </section>
  );
}

export function ScansScreen({ view }: { view: ScanView }) {
  const [showDerived, setShowDerived] = useState(false);
  const [offset, setOffset] = useState(0);
  const [nonce, setNonce] = useState(0);

  // A new scan (from the topline's Run scan) grows the loaded list; the page follows.
  const history = useRemote(`scans:${showDerived}:${offset}:${nonce}:${view.scans.length}`, () =>
    loadHistory(showDerived, offset),
  );
  const page = history.data?.page ?? null;
  const rows = page?.items ?? [];
  const total = page?.total ?? 0;
  // The range comes from the page the SERVER returned, so it can never
  // describe one page while the table still shows another.
  const shownFrom = page?.offset ?? 0;

  const latest = view.scans.find((s) => s.kind === "scan") ?? null;
  const latestStatus = latest ? scanStatus(latest) : null;
  const system = view.scan?.target.system ?? view.scan?.target.ref;

  const statuses = rows.map(scanStatus);
  const complete = statuses.filter((s) => s.status === "COMPLETE").length;
  const partial = statuses.filter((s) => s.status === "PARTIAL" || s.status === "UNKNOWN").length;
  const icon = "h-[13px] w-[13px]";

  function refresh() {
    view.reload();
    setNonce((n) => n + 1);
  }

  return (
    <div className="content">
      <ScreenHeader
        title="Scan History"
        subtitle={
          system
            ? `Security scan executions across ${system}. Rescore and fix passes are linked rows of their parent, never edits of it.`
            : "Security scan executions stored in this database."
        }
      />

      {history.data ? (
        <div className="stat-row of4 in" style={{ animationDelay: "0.04s" }}>
          <MetricCard
            id="scans-total"
            label="Total scans"
            icon={<Layers className={icon} />}
            measured={computed(
              history.data.originals,
              `${history.data.originals} scans stored · ${history.data.derived} derived rescore / fix rows`,
            )}
            note={`+${history.data.derived} derived`}
          />
          <MetricCard
            id="scans-complete"
            label="Complete"
            icon={<CheckCircle2 className={icon} />}
            measured={computed(complete, `${complete} of the ${rows.length} rows on this page derive as COMPLETE`)}
            note={`of ${rows.length} on this page`}
          />
          <MetricCard
            id="scans-duration"
            label="Avg. duration"
            icon={<Clock className={icon} />}
            measured={notComputed("the store records when a scan was saved, not when it began")}
          />
          <MetricCard
            id="scans-partial"
            label="Partial / unknown"
            icon={<AlertTriangle className={icon} />}
            measured={computed(
              partial,
              "rows on this page whose scanner record is partial or missing; a failed job stores no row",
            )}
            note="this page"
          />
        </div>
      ) : (
        <div className="stat-row of4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="stat-card h-[5.75rem] animate-pulse" />
          ))}
        </div>
      )}

      <Timeline view={view} />

      <section className="panel in" style={{ animationDelay: "0.12s" }}>
        <PanelHead
          title="Scan history"
          sub={`${pad2(total)} record${total === 1 ? "" : "s"}${system ? ` · all runs stored in this database` : ""}`}
          right={
            <div className="flex shrink-0 items-center gap-2">
              {latestStatus ? (
                <Prov
                  kind={latestStatus.status === "COMPLETE" ? "verified" : latestStatus.status === "PARTIAL" ? "provisional" : "unavailable"}
                  title={latestStatus.reason}
                >
                  Latest {latestStatus.status.toLowerCase()}
                </Prov>
              ) : null}
              <button
                type="button"
                aria-pressed={showDerived}
                onClick={() => {
                  setShowDerived((value) => !value);
                  setOffset(0);
                }}
                title="Each Mosca slider move stores a rescore row; they are hidden unless asked for"
                className="filter-chip"
              >
                Derived rows <span className="count">{history.data ? history.data.derived : "…"}</span>
              </button>
              <button type="button" aria-label="Refresh" title="Reload the scan list" onClick={refresh} className="icon-btn">
                <RefreshCw className="h-3.5 w-3.5" aria-hidden />
              </button>
            </div>
          }
        />
        {history.error ? (
          <EmptyState title="Scan history could not be loaded">
            {history.error}. This is a failed request, not an empty database.
          </EmptyState>
        ) : total === 0 && !history.loading ? (
          <EmptyState title="No scans stored in this database">
            Start one with <strong className="text-ink-dim">Run scan</strong>, or run{" "}
            <code className="mono">ecdat scan</code> with the same <code className="mono">ECDAT_DB</code> the server
            opened.
          </EmptyState>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="queue-table">
                <thead>
                  <tr>
                    <th>Scan</th>
                    <th>System</th>
                    <th>Started</th>
                    <th>Completed</th>
                    <th className="text-right">Artefacts</th>
                    <th className="text-right">Critical</th>
                    <th className="text-right">High</th>
                    <th className="text-right">Drift</th>
                    <th>Status</th>
                    <th>
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
                      >
                        <td>
                          <div className="qt-mono font-semibold text-ink">{scan.target.ref}</div>
                          <div className="qt-sub flex items-center gap-2">
                            <span className="mono">
                              {scan.id.slice(0, 8)} · {scan.target.kind}
                            </span>
                            {scan.kind !== "scan" ? (
                              <span className="mark" title={`derived from ${scan.parent_scan_id ?? "unknown"}`}>
                                {scan.kind} of {scan.parent_scan_id?.slice(0, 8) ?? "?"}
                              </span>
                            ) : null}
                          </div>
                        </td>
                        <td className="text-ink-dim">{scan.target.system ?? "—"}</td>
                        <td
                          className="qt-mono whitespace-nowrap text-[11.5px] text-ink-faint"
                          title="The store records when a scan was saved, not when it began"
                        >
                          not recorded
                        </td>
                        <td className="qt-mono whitespace-nowrap text-[11.5px]" title="UTC">
                          {formatDateTime(scan.created_at)}
                        </td>
                        <td className="qt-mono text-right tabular-nums">{scan.component_count}</td>
                        <td className="qt-mono text-right tabular-nums">
                          <BandCount band="Critical" n={scan.band_counts.Critical ?? 0} />
                        </td>
                        <td className="qt-mono text-right tabular-nums">
                          <BandCount band="High" n={scan.band_counts.High ?? 0} />
                        </td>
                        <td className="qt-mono text-right tabular-nums">{driftCell(scan)}</td>
                        <td>
                          <Prov
                            kind={
                              status.status === "COMPLETE"
                                ? "verified"
                                : status.status === "PARTIAL"
                                  ? "provisional"
                                  : "unavailable"
                            }
                            title={status.reason}
                          >
                            {status.status}
                          </Prov>
                        </td>
                        <td className="text-right">
                          <button
                            type="button"
                            onClick={(event) => {
                              event.stopPropagation();
                              view.selectScan(scan.id);
                              navigate("overview");
                            }}
                            className="inline-flex items-center gap-1 text-[12px] font-semibold text-ink-dim transition-colors hover:text-ink"
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
            <div className="pager">
              <span>
                {rows.length > 0 ? (
                  <>
                    Showing {shownFrom + 1}–{shownFrom + rows.length} of {total}
                  </>
                ) : (
                  "Loading…"
                )}
              </span>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  className="icon-btn"
                  aria-label="Previous page"
                  disabled={history.loading || shownFrom === 0}
                  onClick={() => setOffset(Math.max(0, shownFrom - SCANS_PAGE_SIZE))}
                >
                  <ChevronLeft className="h-3.5 w-3.5" aria-hidden />
                </button>
                <button
                  type="button"
                  className="icon-btn"
                  aria-label="Next page"
                  disabled={history.loading || shownFrom + rows.length >= total}
                  onClick={() => setOffset(shownFrom + SCANS_PAGE_SIZE)}
                >
                  <ChevronRight className="h-3.5 w-3.5" aria-hidden />
                </button>
              </div>
            </div>
          </>
        )}
      </section>
    </div>
  );
}
