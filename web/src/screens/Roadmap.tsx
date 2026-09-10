/**
 * MIGRATION ROADMAP -- the deadline sequence as a Gantt, laid out as web/design/
 * has it (ADR-0032): year columns, a two-line label per row, the bar with its
 * date inside, band and hybrid on the right, and deadline-cluster cards below.
 *
 * A bar is drawn only where a pack DATED the artefact (`ecdat:deadline`); it
 * runs from this year to the deadline in the artefact's band colour. The
 * undated are listed beneath, never placed on the axis. The target is the
 * pack's LABEL (ADR-0030) -- a family such as ML-DSA, never a parameter set the
 * console chose. No label, no target.
 */
import { Download } from "lucide-react";
import { useMemo } from "react";

import type { Artefact, ScanSummary } from "@/api/types";
import { BANDS } from "@/api/types";
import { EmptyPanel } from "@/components/Honest";
import { BandBadge, Button, Panel, ScreenHeader, Tag } from "@/components/Panel";
import { downloadText } from "@/lib/download";
import { BAND_STYLE, cn } from "@/lib/format";
import { hrefFor } from "@/lib/router";
import { roadmapCsv, roadmapOf, type RoadmapRow } from "@/state/metrics";

const GRID = "grid grid-cols-[minmax(13rem,1fr)_minmax(0,2.4fr)_minmax(9rem,auto)]";

function currentOf(artefact: Artefact): string {
  const bits = artefact.params.key_size;
  return bits && !artefact.name.includes(bits) ? `${artefact.name}-${bits}` : artefact.name;
}

function Row({ row, columns, thisYear }: { row: RoadmapRow; columns: string[]; thisYear: string }) {
  const end = columns.indexOf(row.column);
  const start = row.overdue ? 0 : 1;
  const style = BAND_STYLE[row.artefact.band];
  return (
    <div className={cn(GRID, "items-stretch border-t border-line")}>
      <div className="min-w-0 py-3 pr-3">
        <a
          href={hrefFor("inventory", { ref: row.artefact.bomRef })}
          className="block truncate text-[13px] font-medium text-ink hover:underline"
        >
          {row.artefact.name} <span className="font-normal text-ink-dim">{row.artefact.usage}</span>
        </a>
        <div className="mt-0.5 truncate font-mono text-[11px] text-ink-faint">
          {currentOf(row.artefact)} → {row.target ?? "no target labelled by a pack"}
        </div>
      </div>
      <div className="relative grid grid-cols-5 items-center">
        {columns.map((column, index) => (
          <div
            key={column}
            className={cn("h-full border-l", column === thisYear ? "border-ink-faint/50" : "border-line")}
            style={{ gridColumn: index + 1, gridRow: 1 }}
          />
        ))}
        <div
          data-testid="roadmap-bar"
          title={`${row.artefact.name}: due ${row.deadline}${row.provisional ? " (provisional)" : ""}${row.overdue ? " — overdue" : ""}`}
          style={{ gridColumn: `${start + 1} / ${end + 2}`, gridRow: 1 }}
          className={cn(
            "mx-1.5 flex h-6 items-center self-center rounded-[3px] px-2",
            row.provisional ? cn("border border-dashed", style.bg) : style.dot,
          )}
        >
          <span
            className={cn(
              "truncate font-mono text-[10px] font-medium tabular-nums",
              row.provisional ? "text-ink-faint line-through" : "text-ground",
            )}
          >
            {row.overdue ? `overdue · ${row.deadline}` : row.deadline}
          </span>
        </div>
      </div>
      <div className="flex flex-wrap items-center justify-end gap-1.5 py-3 pl-3">
        <BandBadge band={row.artefact.band} />
        {row.hybrid === true ? <Tag>Hybrid</Tag> : null}
        {row.hybrid === false ? <Tag>Classical</Tag> : null}
        {row.provisional ? <Tag variant="provisional">Provisional date</Tag> : null}
      </div>
    </div>
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

  return (
    <div>
      <ScreenHeader
        title="Migration Roadmap"
        subtitle={`Sequence PQC migration work against the knowledge packs' deadlines, as of ${day}. A bar runs from this year to its deadline in the artefact's band colour; a dashed bar is a provisional date.`}
        actions={
          <Button
            variant="primary"
            disabled={!scan || roadmap.rows.length === 0}
            title="CSV of the dated rows, generated in the browser"
            onClick={() =>
              scan && downloadText(`qorbit-roadmap-${scan.id.slice(0, 8)}.csv`, roadmapCsv(roadmap.rows), "text/csv")
            }
          >
            <Download className="h-3.5 w-3.5" aria-hidden /> Export roadmap
          </Button>
        }
      />
      <div className="space-y-4 px-6 pb-6">
        {!scan ? (
          <EmptyPanel title="No scan selected" />
        ) : roadmap.rows.length === 0 ? (
          <EmptyPanel title="No artefact in this scan carries a deadline">
            No knowledge pack assigned a date to anything found here, so there is no sequence to
            draw. The undated artefacts are listed below.
          </EmptyPanel>
        ) : (
          <Panel
            eyebrow={`Migration program / ${roadmap.rows.length} dated artefact${roadmap.rows.length === 1 ? "" : "s"}`}
            title="Deadline sequence"
            meta={
              <span className="flex flex-wrap items-center gap-3 font-mono text-[10.5px]">
                {BANDS.map((band) => (
                  <span key={band} className="flex items-center gap-1.5">
                    <span className={cn("h-2 w-2 rounded-full", BAND_STYLE[band].dot)} aria-hidden />
                    {band.toLowerCase()}
                  </span>
                ))}
                <span className="flex items-center gap-1.5">
                  <span className="h-2 w-3 rounded-[2px] border border-dashed border-ink-faint" aria-hidden />
                  provisional
                </span>
              </span>
            }
          >
            <div className={cn(GRID, "items-end pb-2")}>
              <div />
              <div className="grid grid-cols-5">
                {roadmap.columns.map((column) => (
                  <div
                    key={column}
                    className={cn(
                      "px-2 font-mono text-[11px]",
                      column === thisYear
                        ? "border-l-2 border-ink-dim font-semibold text-ink"
                        : "border-l border-line text-ink-faint",
                    )}
                  >
                    {column === "overdue" ? "Overdue" : column}
                  </div>
                ))}
              </div>
              <div />
            </div>
            {roadmap.rows.map((row) => (
              <Row key={row.artefact.bomRef} row={row} columns={roadmap.columns} thisYear={thisYear} />
            ))}
          </Panel>
        )}

        {roadmap.clusters.length > 0 ? (
          <div className="grid gap-4 md:grid-cols-3">
            {roadmap.clusters.map((cluster) => {
              const worst = BANDS.find((band) => cluster.rows.some((row) => row.artefact.band === band)) ?? "Low";
              const labels = [...new Set(cluster.rows.flatMap((row) => row.artefact.labels.filter((l) => l.startsWith("dst-"))))];
              const overdue = cluster.rows.some((row) => row.overdue);
              return (
                <div key={cluster.deadline} className="rounded-lg border border-line bg-panel p-5">
                  <div className="eyebrow">Deadline cluster</div>
                  <div className="mt-2 flex items-start justify-between gap-3">
                    <div>
                      <div className="text-[28px] font-semibold leading-none tabular-nums text-ink">
                        {cluster.deadline.slice(0, 4)}
                      </div>
                      <div className="mt-1 font-mono text-[11px] text-ink-faint">
                        {cluster.deadline}
                        {overdue ? " · overdue" : ""}
                      </div>
                    </div>
                    <BandBadge band={worst} />
                  </div>
                  <div className="mt-3 text-[12px] text-ink-dim">
                    {cluster.rows.length} artefact{cluster.rows.length === 1 ? "" : "s"}
                    {labels.length > 0 ? ` · ${labels.join(", ")}` : ""}
                  </div>
                </div>
              );
            })}
          </div>
        ) : null}

        {scan ? (
          <Panel eyebrow="Not on the axis" title={`No deadline (${roadmap.undated.length})`} bodyClassName="pt-1">
            {roadmap.undated.length === 0 ? (
              <p className="text-[12px] text-ink-faint">Every artefact carries a deadline.</p>
            ) : (
              <ul>
                {roadmap.undated.map((artefact) => (
                  <li
                    key={artefact.bomRef}
                    data-testid="roadmap-undated-item"
                    className="flex items-baseline gap-3 border-t border-line py-2 first:border-t-0"
                  >
                    <span className={cn("h-1.5 w-1.5 self-center rounded-full", BAND_STYLE[artefact.band].dot)} aria-hidden />
                    <a href={hrefFor("inventory", { ref: artefact.bomRef })} className="text-[13px] text-ink-dim hover:text-ink">
                      {artefact.name}
                    </a>
                    <span className="ml-auto text-[11px] text-ink-faint">no pack assigned a deadline</span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        ) : null}
      </div>
    </div>
  );
}
