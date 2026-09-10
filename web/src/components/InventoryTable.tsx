/**
 * The inventory: the centrepiece, and the thing that makes this read as a
 * security console rather than a report.
 *
 * Dense on purpose. Row height is 30px, borders are 1px, and every technical
 * value -- bom-ref, endpoint, deadline, score -- is monospaced and tabular so
 * a column of them lines up and can be scanned vertically. A reader looking
 * for the worst thing in an estate should find it without scrolling.
 */
import { ArrowDown, ArrowUp, GitCompareArrows } from "lucide-react";

import type { Artefact, Band, View } from "@/api/types";
import { BANDS, VIEWS } from "@/api/types";
import { BAND_STYLE, cn, shortLocator, shortRef } from "@/lib/format";
import type { Filters, Sort, SortColumn } from "@/state/inventory";

interface Props {
  rows: Artefact[];
  total: number;
  sort: Sort;
  filters: Filters;
  selected: string | null;
  onSort: (column: SortColumn) => void;
  onFilters: (filters: Filters) => void;
  onSelect: (artefact: Artefact) => void;
}

const VIEW_STYLE: Record<string, string> = {
  declared: "text-sky-300/90 border-sky-400/30 bg-sky-400/5",
  shipped: "text-violet-300/90 border-violet-400/30 bg-violet-400/5",
  observed: "text-emerald-300/90 border-emerald-400/30 bg-emerald-400/5",
};

function BandPill({ band }: { band: Band }) {
  const style = BAND_STYLE[band];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 border px-1.5 py-px text-2xs font-medium",
        style.bg,
        style.text,
      )}
    >
      <span className={cn("h-1.5 w-1.5", style.dot)} />
      {band}
    </span>
  );
}

function Chip({
  active,
  onClick,
  children,
  className,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        "border px-2 py-0.5 text-2xs transition-colors",
        active
          ? "border-accent/60 bg-accent/10 text-accent"
          : "border-line bg-panel text-ink-dim hover:border-line-soft hover:text-ink",
        className,
      )}
    >
      {children}
    </button>
  );
}

function toggle<T>(values: T[], value: T): T[] {
  return values.includes(value)
    ? values.filter((v) => v !== value)
    : [...values, value];
}

const COLUMNS: { key: SortColumn; label: string; className?: string }[] = [
  { key: "name", label: "Artefact", className: "w-[26%]" },
  { key: "view", label: "View", className: "w-[8%]" },
  { key: "band", label: "Band", className: "w-[9%]" },
  { key: "score", label: "Score", className: "w-[6%] text-right" },
  { key: "usage", label: "Usage", className: "w-[10%]" },
  { key: "endpoint", label: "Endpoint / location", className: "w-[27%]" },
  { key: "deadline", label: "Deadline", className: "w-[10%]" },
];

export function InventoryTable({
  rows,
  total,
  sort,
  filters,
  selected,
  onSort,
  onFilters,
  onSelect,
}: Props) {
  return (
    <section className="flex min-h-0 flex-1 flex-col">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-line bg-panel px-4 py-2">
        <input
          value={filters.query}
          onChange={(e) => onFilters({ ...filters, query: e.target.value })}
          placeholder="Filter by name, bom-ref, endpoint, file…"
          className={cn(
            "h-7 w-64 border border-line bg-ground px-2 text-xs text-ink",
            "placeholder:text-ink-faint focus:border-accent/60 focus:outline-none",
          )}
        />
        <div className="flex items-center gap-1">
          <span className="mr-1 text-2xs uppercase tracking-widest text-ink-faint">
            Band
          </span>
          {BANDS.map((band) => (
            <Chip
              key={band}
              active={filters.bands.includes(band)}
              onClick={() =>
                onFilters({ ...filters, bands: toggle(filters.bands, band) })
              }
            >
              {band}
            </Chip>
          ))}
        </div>
        <div className="flex items-center gap-1">
          <span className="mr-1 text-2xs uppercase tracking-widest text-ink-faint">
            View
          </span>
          {VIEWS.map((view: View) => (
            <Chip
              key={view}
              active={filters.views.includes(view)}
              onClick={() =>
                onFilters({ ...filters, views: toggle(filters.views, view) })
              }
            >
              {view}
            </Chip>
          ))}
        </div>
        <Chip
          active={filters.driftOnly}
          onClick={() => onFilters({ ...filters, driftOnly: !filters.driftOnly })}
        >
          <span className="flex items-center gap-1">
            <GitCompareArrows className="h-3 w-3" aria-hidden />
            Drift only
          </span>
        </Chip>
        <span className="ml-auto font-mono text-2xs text-ink-faint">
          {rows.length === total ? `${total}` : `${rows.length} / ${total}`} shown
        </span>
      </div>

      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full border-collapse text-xs">
          <thead className="sticky top-0 z-10">
            <tr className="bg-raised">
              {COLUMNS.map((column) => {
                const active = sort.column === column.key;
                return (
                  <th
                    key={column.key}
                    className={cn(
                      "border-b border-line px-3 py-1.5 text-left font-medium",
                      column.className,
                    )}
                  >
                    <button
                      type="button"
                      onClick={() => onSort(column.key)}
                      className={cn(
                        "inline-flex items-center gap-1 text-2xs uppercase tracking-widest transition-colors",
                        active ? "text-ink" : "text-ink-faint hover:text-ink-dim",
                      )}
                    >
                      {column.label}
                      {active ? (
                        sort.direction === "desc" ? (
                          <ArrowDown className="h-3 w-3" aria-hidden />
                        ) : (
                          <ArrowUp className="h-3 w-3" aria-hidden />
                        )
                      ) : null}
                    </button>
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {rows.map((artefact) => {
              const isSelected = artefact.bomRef === selected;
              const location =
                artefact.endpoint ??
                (artefact.occurrences[0]
                  ? shortLocator(artefact.occurrences[0].locator)
                  : "—");
              return (
                <tr
                  key={artefact.bomRef}
                  onClick={() => onSelect(artefact)}
                  className={cn(
                    "cursor-pointer border-b border-line-soft transition-colors",
                    isSelected ? "bg-accent/10" : "hover:bg-raised/70",
                  )}
                >
                  <td className="px-3 py-1.5">
                    <div className="flex items-baseline gap-2">
                      <span className="truncate font-medium text-ink">
                        {artefact.name}
                      </span>
                      <span className="shrink-0 font-mono text-2xs text-ink-faint">
                        {shortRef(artefact.bomRef)}
                      </span>
                      {artefact.drift.length > 0 ? (
                        <GitCompareArrows
                          className="h-3 w-3 shrink-0 text-high"
                          aria-label="drift"
                        />
                      ) : null}
                      {artefact.provisional ? (
                        <span className="shrink-0 border border-dashed border-ink-faint/60 px-1 text-[9px] uppercase tracking-wide text-ink-faint">
                          prov
                        </span>
                      ) : null}
                    </div>
                  </td>
                  <td className="px-3 py-1.5">
                    <span
                      className={cn(
                        "border px-1.5 py-px text-2xs",
                        VIEW_STYLE[artefact.view] ??
                          "border-line text-ink-dim bg-panel",
                      )}
                    >
                      {artefact.view}
                    </span>
                  </td>
                  <td className="px-3 py-1.5">
                    <BandPill band={artefact.band} />
                  </td>
                  <td
                    className={cn(
                      "px-3 py-1.5 text-right font-mono tabular-nums",
                      BAND_STYLE[artefact.band].text,
                    )}
                  >
                    {artefact.score}
                  </td>
                  <td className="px-3 py-1.5 text-ink-dim">{artefact.usage}</td>
                  <td className="px-3 py-1.5">
                    <span className="block truncate font-mono text-2xs text-ink-dim">
                      {location}
                    </span>
                  </td>
                  <td className="px-3 py-1.5">
                    <span
                      className={cn(
                        "font-mono text-2xs",
                        artefact.deadlineProvisional
                          ? "text-ink-faint line-through decoration-dotted"
                          : "text-ink-dim",
                      )}
                      title={
                        artefact.deadlineProvisional
                          ? "Provisional: this deadline comes from a rule nobody has confirmed against its source"
                          : undefined
                      }
                    >
                      {artefact.deadline ?? "—"}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {rows.length === 0 ? (
          <div className="px-4 py-10 text-center text-xs text-ink-faint">
            No artefact matches these filters.
            {filters.driftOnly ? (
              <span className="mt-1 block">
                Drift needs all three views in one document; a single-target scan
                has only one.
              </span>
            ) : null}
          </div>
        ) : null}
      </div>
    </section>
  );
}
