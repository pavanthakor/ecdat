/**
 * MIGRATION ROADMAP -- rebuilt on the v2 mockup (roadmap.html; ADR-0039): the
 * Gantt of dated artefacts with the deadline cards under it, then the two
 * highest-risk dated artefacts in detail, then everything with no deadline.
 *
 * A bar is drawn only where a pack DATED the artefact (`ecdat:deadline`); it
 * runs from this year to the deadline in the artefact's band colour, and a
 * provisional date is a dashed band outline. The undated are listed beneath,
 * never placed on the axis. The target is the pack's LABEL (ADR-0030) -- a
 * family such as ML-DSA, never a parameter set the console chose; no label,
 * no target. The mockup's "Sort by deadline" control is not reproduced: the
 * rows are already in deadline order, and a menu with one choice is a lie.
 */
import { Download } from "lucide-react";
import { useMemo, type CSSProperties } from "react";

import type { Artefact, ScanSummary } from "@/api/types";
import { BANDS } from "@/api/types";
import { ScreenHeader } from "@/components/Panel";
import { BandTag, EmptyState, PanelHead, tone, useGrown } from "@/components/v2";
import { downloadText } from "@/lib/download";
import { cn, shortLocator } from "@/lib/format";
import { hrefFor } from "@/lib/router";
import { roadmapCsv, roadmapOf, sortByRisk, type RoadmapRow } from "@/state/metrics";

function currentOf(artefact: Artefact): string {
  const bits = artefact.params.key_size;
  return bits && !artefact.name.includes(bits) ? `${artefact.name}-${bits}` : artefact.name;
}

function placeOf(artefact: Artefact): string {
  return (
    artefact.endpoint ??
    (artefact.occurrences[0] ? shortLocator(artefact.occurrences[0].locator) : "no location recorded")
  );
}

function GanttRow({ row, columns, grown }: { row: RoadmapRow; columns: string[]; grown: boolean }) {
  const n = columns.length;
  const end = Math.max(columns.indexOf(row.column), 0);
  const start = row.overdue ? 0 : Math.min(1, end);
  const left = (start / n) * 100;
  const width = ((end + 1 - start) / n) * 100;
  const { artefact } = row;
  const hybrid = row.hybrid === true ? " · hybrid" : row.hybrid === false ? " · classical" : "";
  return (
    <div className="gantt-row">
      <div className="gantt-label">
        <a href={hrefFor("inventory", { ref: artefact.bomRef })} className="truncate hover:underline">
          {artefact.name} <span className="font-normal text-ink-dim">{artefact.usage}</span>
        </a>
        <small title={`${currentOf(artefact)} → ${row.target ?? "no target labelled by a pack"}`}>
          {currentOf(artefact)} → {row.target ?? "no target labelled by a pack"}
          {hybrid}
        </small>
      </div>
      <div className="gantt-track">
        <div
          data-testid="roadmap-bar"
          data-band={artefact.band}
          title={`${artefact.name}: ${artefact.band}, due ${row.deadline}${row.provisional ? " (provisional date)" : ""}${row.overdue ? " — overdue" : ""}`}
          className={cn(
            "gantt-bar",
            row.provisional ? `provisional band-border-${tone(artefact.band)}` : `band-bg-${tone(artefact.band)}`,
          )}
          style={{ left: `${left}%`, width: grown ? `${width}%` : 0 }}
        >
          <span className={row.provisional ? "line-through" : undefined}>
            {row.overdue ? `overdue · ${row.deadline}` : row.deadline}
          </span>
        </div>
      </div>
    </div>
  );
}

function DetailPanel({ row }: { row: RoadmapRow }) {
  const { artefact } = row;
  return (
    <section className="panel" data-testid="roadmap-detail">
      <PanelHead
        title={
          <a href={hrefFor("inventory", { ref: artefact.bomRef })} className="hover:underline">
            {artefact.name}
          </a>
        }
        sub={placeOf(artefact)}
        right={<BandTag band={artefact.band} />}
      />
      <div className="bar-metric">
        <div className="bar-metric-row">
          <span>Risk score</span>
          <span className="mono">{artefact.score}</span>
        </div>
        <div className="bar-metric-track">
          <div
            data-band={artefact.band}
            className={`bar-metric-fill band-bg-${tone(artefact.band)}`}
            style={{ width: `${artefact.score}%` }}
          />
        </div>
      </div>
      <div className="mt-4 flex flex-wrap justify-between gap-2 text-[11.5px] text-ink-faint">
        <span>Current: {currentOf(artefact)}</span>
        <span>Due {row.deadline}{row.provisional ? " (provisional)" : ""}</span>
        <span>Target: {row.target ?? "no target labelled by a pack"}</span>
      </div>
    </section>
  );
}

export function RoadmapScreen({
  artefacts,
  scan,
  today,
}: {
  artefacts: Artefact[];
  scan: ScanSummary | null;
  today?: string;
}) {
  const day = today ?? new Date().toISOString().slice(0, 10);
  const roadmap = useMemo(() => roadmapOf(artefacts, day), [artefacts, day]);
  const thisYear = day.slice(0, 4);
  const grown = useGrown();
  const featured = useMemo(() => {
    const worst = sortByRisk(roadmap.rows.map((row) => row.artefact)).slice(0, 2);
    return worst.map((artefact) => roadmap.rows.find((row) => row.artefact === artefact)!);
  }, [roadmap.rows]);

  return (
    <div className="content">
      <ScreenHeader
        title="Migration Roadmap"
        subtitle={`Sequence cryptographic migration work against the knowledge packs' deadlines, as of ${day}.`}
      />

      {!scan ? (
        <EmptyState title="No scan selected" />
      ) : roadmap.rows.length === 0 ? (
        <EmptyState title="No artefact in this scan carries a deadline">
          No knowledge pack assigned a date to anything found here, so there is no sequence to draw. The undated
          artefacts are listed below.
        </EmptyState>
      ) : (
        <section className="panel in mb-3" data-testid="roadmap-gantt" style={{ animationDelay: "0.04s" }}>
          <PanelHead
            title="Migration roadmap"
            sub={`${roadmap.rows.length} dated artefact${roadmap.rows.length === 1 ? "" : "s"}, sequenced against exposure deadlines · a dashed bar is a provisional date`}
            right={
              <button
                type="button"
                className="btn-ghost"
                title="CSV of the dated rows, generated in the browser"
                onClick={() => downloadText(`ecdat-roadmap-${scan.id.slice(0, 8)}.csv`, roadmapCsv(roadmap.rows), "text/csv")}
              >
                Export roadmap <Download className="h-3.5 w-3.5" aria-hidden />
              </button>
            }
          />
          <div className="overflow-x-auto">
            <div className="min-w-[640px]" style={{ "--cols": roadmap.columns.length } as CSSProperties}>
              <div className="gantt-head">
                <div>Artefact</div>
                {roadmap.columns.map((column) => (
                  <div key={column} className={column === thisYear ? "now" : undefined}>
                    {column === "overdue" ? "Overdue" : column}
                  </div>
                ))}
              </div>
              {roadmap.rows.map((row) => (
                <GanttRow key={row.artefact.bomRef} row={row} columns={roadmap.columns} grown={grown} />
              ))}
            </div>
          </div>

          {roadmap.clusters.length > 0 ? (
            <div className="deadline-summary">
              {roadmap.clusters.map((cluster) => {
                const worst = BANDS.find((band) => cluster.rows.some((row) => row.artefact.band === band)) ?? "Low";
                const labels = [
                  ...new Set(cluster.rows.flatMap((row) => row.artefact.labels.filter((l) => l.startsWith("dst-")))),
                ];
                const overdue = cluster.rows.some((row) => row.overdue);
                return (
                  <div key={cluster.deadline} className="deadline-card" data-testid="deadline-card">
                    <div className="flex items-start justify-between gap-2">
                      <div className="deadline-year">{cluster.deadline.slice(0, 4)}</div>
                      <BandTag band={worst} />
                    </div>
                    <div className="deadline-count">
                      {cluster.rows.length} asset{cluster.rows.length === 1 ? "" : "s"} · due {cluster.deadline}
                    </div>
                    <div className="deadline-note">
                      {overdue ? "overdue" : labels.length > 0 ? labels.join(", ") : "no roadmap label"}
                    </div>
                  </div>
                );
              })}
            </div>
          ) : null}
        </section>
      )}

      {featured.length > 0 ? (
        <div className="grid-row grid-2 in" style={{ animationDelay: "0.1s" }}>
          {featured.map((row) => (
            <DetailPanel key={row.artefact.bomRef} row={row} />
          ))}
        </div>
      ) : null}

      {scan ? (
        <section className="panel in" style={{ animationDelay: "0.14s" }}>
          <PanelHead
            title={`No deadline (${roadmap.undated.length})`}
            sub="Not on the axis: no pack assigned these a date, so they are listed, never placed"
          />
          {roadmap.undated.length === 0 ? (
            <p className="page-sub mt-3">Every artefact carries a deadline.</p>
          ) : (
            <ul className="mt-2">
              {roadmap.undated.map((artefact) => (
                <li key={artefact.bomRef} data-testid="roadmap-undated-item" className="improve-row">
                  <div className="flex min-w-0 items-center gap-3">
                    <span
                      data-band={artefact.band}
                      className={`h-1.5 w-1.5 shrink-0 rounded-full band-bg-${tone(artefact.band)}`}
                      aria-hidden
                    />
                    <a
                      href={hrefFor("inventory", { ref: artefact.bomRef })}
                      className="truncate text-[12.5px] font-semibold text-ink-dim hover:text-ink"
                    >
                      {artefact.name}
                    </a>
                  </div>
                  <span className="text-[11px] text-ink-faint">no pack assigned a deadline</span>
                  <span />
                </li>
              ))}
            </ul>
          )}
        </section>
      ) : null}
    </div>
  );
}
