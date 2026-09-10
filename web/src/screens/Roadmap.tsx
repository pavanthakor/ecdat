/**
 * MIGRATION ROADMAP -- the deadline sequence, as a Gantt.
 *
 * A bar is drawn only where a pack DATED the artefact (`ecdat:deadline`); it
 * runs from today to the deadline and takes the artefact's band colour. The
 * undated are listed beneath, never placed on the axis -- a bar at an invented
 * date is exactly the fake bar the honesty rule forbids.
 *
 * The target is the pack's LABEL (ADR-0030): a family such as ML-DSA, never a
 * parameter set the console chose. No label, no target.
 */
import { Fragment, useMemo } from "react";

import type { Artefact, ScanSummary } from "@/api/types";
import { BANDS } from "@/api/types";
import { EmptyPanel } from "@/components/Honest";
import { Panel, ScreenHeader, Tag } from "@/components/Panel";
import { BAND_STYLE, cn, shortRef } from "@/lib/format";
import { hrefFor } from "@/lib/router";
import { roadmapOf, type RoadmapRow } from "@/state/metrics";

const GRID = "grid grid-cols-[minmax(15rem,1.1fr)_3fr]";

function currentOf(artefact: Artefact): string {
  const bits = artefact.params.key_size;
  return bits && !artefact.name.includes(bits) ? `${artefact.name} · ${bits}-bit` : artefact.name;
}

function Row({ row, columns }: { row: RoadmapRow; columns: string[] }) {
  const end = columns.indexOf(row.column);
  const start = row.overdue ? 0 : 1;
  const style = BAND_STYLE[row.artefact.band];
  return (
    <div className={cn(GRID, "border-b border-line-soft")}>
      <div className="min-w-0 px-3 py-1.5">
        <div className="flex items-baseline gap-2">
          <a
            href={hrefFor("inventory", { ref: row.artefact.bomRef })}
            className="truncate text-xs font-medium text-ink hover:underline"
          >
            {currentOf(row.artefact)}
          </a>
          <span className="shrink-0 font-mono text-[10px] text-ink-faint">
            {shortRef(row.artefact.bomRef)}
          </span>
        </div>
        <div className="mt-0.5 flex flex-wrap items-center gap-1.5 text-2xs">
          <span className="text-ink-faint">{row.artefact.usage}</span>
          <span className="text-ink-faint">→</span>
          {row.target ? (
            <span className="font-mono text-ink-dim">{row.target}</span>
          ) : (
            <span className="text-ink-faint">no target labelled by a pack</span>
          )}
          {row.hybrid === true ? <Tag>Hybrid</Tag> : null}
          {row.hybrid === false ? <Tag>Classical</Tag> : null}
        </div>
      </div>
      <div className="relative grid grid-cols-5 items-center">
        {columns.map((column, index) => (
          <div
            key={column}
            className="h-full border-l border-line-soft"
            style={{ gridColumn: index + 1, gridRow: 1 }}
          />
        ))}
        <div
          data-testid="roadmap-bar"
          title={`${row.artefact.name}: due ${row.deadline}${row.provisional ? " (provisional)" : ""}${row.overdue ? " — overdue" : ""}`}
          style={{ gridColumn: `${start + 1} / ${end + 2}`, gridRow: 1 }}
          className={cn(
            "mx-1 flex h-4 items-center justify-end self-center px-1.5",
            row.provisional
              ? cn("border border-dashed bg-transparent", style.bg)
              : cn(style.dot, "bg-opacity-80"),
          )}
        >
          <span
            className={cn(
              "whitespace-nowrap font-mono text-[9.5px] tabular-nums",
              row.provisional ? "text-ink-faint line-through" : "text-ground",
            )}
          >
            {row.overdue ? `overdue · ${row.deadline}` : row.deadline}
          </span>
        </div>
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
  const labels = (row: RoadmapRow) => row.artefact.labels.filter((l) => l.startsWith("dst-"));

  return (
    <div>
      <ScreenHeader
        title="Migration Roadmap"
        subtitle={`Deadline sequence from the knowledge packs, as of ${day}. A bar runs from today to its deadline in the artefact's band colour; a dashed bar is a provisional (unconfirmed) date.`}
      />
      <div className="space-y-3 p-4">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-2xs text-ink-faint">
          <span className="eyebrow">Urgency</span>
          {BANDS.map((band) => (
            <span key={band} className="flex items-center gap-1.5">
              <span className={cn("h-2 w-3", BAND_STYLE[band].dot)} />
              {band}
            </span>
          ))}
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-3 border border-dashed border-ink-faint" /> provisional date
          </span>
          <Tag>Hybrid</Tag>
          <span>hybrid key exchange declared</span>
        </div>

        {!scan ? (
          <EmptyPanel title="No scan selected" />
        ) : roadmap.rows.length === 0 ? (
          <EmptyPanel title="No artefact in this scan carries a deadline">
            No knowledge pack assigned a date to anything found here, so there is no
            sequence to draw. The undated artefacts are listed below.
          </EmptyPanel>
        ) : (
          <Panel title="Deadline sequence" meta={`${roadmap.rows.length} dated`} bodyClassName="p-0">
            <div className={cn(GRID, "border-b border-line bg-raised")}>
              <div className="px-3 py-1.5 text-2xs uppercase tracking-widest text-ink-faint">
                Artefact · current → target
              </div>
              <div className="grid grid-cols-5">
                {roadmap.columns.map((column) => (
                  <div
                    key={column}
                    className={cn(
                      "border-l border-line px-2 py-1.5 font-mono text-2xs uppercase tracking-wider",
                      column === "overdue" ? "text-critical" : "text-ink-faint",
                    )}
                  >
                    {column}
                  </div>
                ))}
              </div>
            </div>
            {roadmap.clusters.map((cluster) => {
              const shared = [...new Set(cluster.rows.flatMap(labels))];
              return (
                <Fragment key={cluster.deadline}>
                  <div className="flex flex-wrap items-center gap-2 border-b border-line-soft bg-ground px-3 py-1">
                    <span className="font-mono text-2xs text-ink-dim">{cluster.deadline}</span>
                    <span className="text-[10px] text-ink-faint">
                      {cluster.rows.length} artefact{cluster.rows.length === 1 ? "" : "s"}
                    </span>
                    {shared.map((label) => (
                      <Tag key={label}>{label}</Tag>
                    ))}
                  </div>
                  {cluster.rows.map((row) => (
                    <Row key={row.artefact.bomRef} row={row} columns={roadmap.columns} />
                  ))}
                </Fragment>
              );
            })}
          </Panel>
        )}

        {scan ? (
          <Panel title={`No deadline (${roadmap.undated.length})`} bodyClassName="p-0">
            {roadmap.undated.length === 0 ? (
              <p className="px-3 py-2 text-2xs text-ink-faint">Every artefact carries a deadline.</p>
            ) : (
              <ul>
                {roadmap.undated.map((artefact) => (
                  <li
                    key={artefact.bomRef}
                    data-testid="roadmap-undated-item"
                    className="flex items-baseline gap-3 border-b border-line-soft px-3 py-1 last:border-b-0"
                  >
                    <span className={cn("h-1.5 w-1.5 self-center", BAND_STYLE[artefact.band].dot)} />
                    <a
                      href={hrefFor("inventory", { ref: artefact.bomRef })}
                      className="text-xs text-ink-dim hover:text-ink"
                    >
                      {artefact.name}
                    </a>
                    <span className="font-mono text-[10px] text-ink-faint">{shortRef(artefact.bomRef)}</span>
                    <span className="ml-auto text-[10px] text-ink-faint">no pack assigned a deadline</span>
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
