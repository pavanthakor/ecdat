/**
 * The inventory: the centrepiece, and what makes this read as a security
 * console rather than a report.
 *
 * Density decisions, taken from how these tables actually get used:
 *
 * * **A 2px left border on Critical and High rows**, not a background fill. A
 *   fill washes out the row's own content and stacks badly when several are
 *   adjacent; an edge marker lets the eye find severity down the left gutter
 *   without competing with anything in the cells.
 * * **Hairline separators, no zebra striping.** Striping encodes nothing, and
 *   it fights the severity accent for the reader's attention.
 * * **Numbers right-aligned and tabular.** Scores and dates line up on their
 *   digits, so a column can be scanned vertically instead of read.
 * * **The artefact name is the strongest thing in its row.** The bom-ref beside
 *   it is smaller, monospaced and muted -- it is an address, not a label.
 * * **Verified vs provisional is a border, not a colour** (ADR-0018): the Facts
 *   column is solid for a verdict resting only on confirmed rules and dashed
 *   for one that includes an unconfirmed (and therefore unscored) rule.
 */
import { ArrowDown, ArrowUp, GitCompareArrows } from "lucide-react";

import type { Artefact, Band, View } from "@/api/types";
import { BANDS, VIEWS } from "@/api/types";
import { BAND_STYLE, cn, shortLocator, shortRef } from "@/lib/format";
import type { Filters, Sort, SortColumn } from "@/state/inventory";
import type { EmptyState } from "@/state/presentation";
import { Tag } from "./Panel";
import { SkeletonRows } from "./Skeleton";

interface Props {
  rows: Artefact[];
  total: number;
  sort: Sort;
  filters: Filters;
  selected: string | null;
  loading: boolean;
  emptyState: EmptyState | null;
  onSort: (column: SortColumn) => void;
  onFilters: (filters: Filters) => void;
  onSelect: (artefact: Artefact) => void;
  onClearFilters: () => void;
}

/** The severity gutter. Only the two bands worth interrupting a scan for. */
const ROW_ACCENT: Record<Band, string> = {
  Critical: "border-l-2 border-l-critical",
  High: "border-l-2 border-l-high",
  Medium: "border-l-2 border-l-transparent",
  Low: "border-l-2 border-l-transparent",
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
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        "border px-2 py-0.5 text-2xs transition-colors",
        active
          ? "border-ink-dim bg-raised text-ink"
          : "border-line bg-panel text-ink-faint hover:border-line-soft hover:text-ink-dim",
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

const COLUMNS: {
  key: string;
  label: string;
  sort?: SortColumn;
  className?: string;
  align?: "right";
}[] = [
  { key: "name", label: "Artefact", sort: "name", className: "w-[25%]" },
  { key: "view", label: "View", sort: "view", className: "w-[7%]" },
  { key: "band", label: "Band", sort: "band", className: "w-[8%]" },
  { key: "score", label: "Score", sort: "score", className: "w-[5%]", align: "right" },
  { key: "usage", label: "Usage", sort: "usage", className: "w-[8%]" },
  { key: "endpoint", label: "Endpoint · location", sort: "endpoint", className: "w-[22%]" },
  { key: "deadline", label: "Deadline", sort: "deadline", className: "w-[9%]", align: "right" },
  { key: "drift", label: "Drift", className: "w-[6%]" },
  { key: "facts", label: "Facts", className: "w-[10%]" },
];

export function InventoryTable({
  rows,
  total,
  sort,
  filters,
  selected,
  loading,
  emptyState,
  onSort,
  onFilters,
  onSelect,
  onClearFilters,
}: Props) {
  return (
    <section className="flex min-h-0 flex-1 flex-col">
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-b border-line bg-panel px-4 py-2">
        <input
          value={filters.query}
          onChange={(e) => onFilters({ ...filters, query: e.target.value })}
          placeholder="Filter artefacts…"
          aria-label="Filter artefacts"
          className={cn(
            "h-7 w-56 border border-line bg-ground px-2 text-xs text-ink",
            "placeholder:text-ink-faint focus:border-ink-faint focus:outline-none",
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
          Drift only
        </Chip>
        <span className="ml-auto font-mono text-2xs tabular-nums text-ink-faint">
          {rows.length === total ? total : `${rows.length} / ${total}`}
        </span>
      </div>

      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full border-collapse text-xs">
          <thead className="sticky top-0 z-10">
            <tr className="bg-raised">
              {COLUMNS.map((column) => {
                const active = column.sort !== undefined && sort.column === column.sort;
                return (
                  <th
                    key={column.key}
                    className={cn(
                      "border-b border-line px-3 py-1.5 font-medium",
                      column.align === "right" ? "text-right" : "text-left",
                      column.className,
                    )}
                  >
                    {column.sort ? (
                      <button
                        type="button"
                        onClick={() => onSort(column.sort as SortColumn)}
                        className={cn(
                          "inline-flex items-center gap-1 text-2xs uppercase tracking-widest transition-colors",
                          active ? "text-ink" : "text-ink-faint hover:text-ink-dim",
                        )}
                      >
                        {column.label}
                        {active ? (
                          sort.direction === "desc" ? (
                            <ArrowDown className="h-2.5 w-2.5" aria-hidden />
                          ) : (
                            <ArrowUp className="h-2.5 w-2.5" aria-hidden />
                          )
                        ) : null}
                      </button>
                    ) : (
                      <span className="text-2xs uppercase tracking-widest text-ink-faint">
                        {column.label}
                      </span>
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <SkeletonRows columns={COLUMNS.length} rows={12} />
            ) : (
              rows.map((artefact) => {
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
                    data-band={artefact.band}
                    className={cn(
                      "cursor-pointer border-b border-line-soft transition-colors",
                      ROW_ACCENT[artefact.band],
                      isSelected ? "bg-raised" : "hover:bg-raised/60",
                    )}
                  >
                    <td className="px-3 py-1">
                      <div className="flex items-baseline gap-2">
                        <span className="truncate text-xs font-medium text-ink">
                          {artefact.name}
                        </span>
                        <span className="shrink-0 font-mono text-[10px] text-ink-faint">
                          {shortRef(artefact.bomRef)}
                        </span>
                      </div>
                    </td>
                    <td className="px-3 py-1">
                      <span className="text-2xs text-ink-dim">{artefact.view}</span>
                    </td>
                    <td className="px-3 py-1">
                      <BandPill band={artefact.band} />
                    </td>
                    <td
                      className={cn(
                        "px-3 py-1 text-right font-mono tabular-nums",
                        BAND_STYLE[artefact.band].text,
                      )}
                    >
                      {artefact.score}
                    </td>
                    <td className="px-3 py-1 text-ink-dim">{artefact.usage}</td>
                    <td className="px-3 py-1">
                      <span
                        className="block truncate font-mono text-[10px] text-ink-dim"
                        title={artefact.endpoint ? "endpoint" : "first sighting — no endpoint recorded"}
                      >
                        {location}
                      </span>
                    </td>
                    <td className="px-3 py-1 text-right">
                      <span
                        className={cn(
                          "font-mono text-[10px] tabular-nums",
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
                    <td className="px-3 py-1">
                      {artefact.drift.length > 0 ? (
                        <span className="inline-flex items-center gap-1 font-mono text-[10px] text-ink">
                          <GitCompareArrows className="h-3 w-3" aria-label="drift" />
                          {artefact.drift.length}
                        </span>
                      ) : (
                        <span className="text-ink-faint">—</span>
                      )}
                    </td>
                    <td className="px-3 py-1">
                      {artefact.provisional ? (
                        <Tag
                          variant="provisional"
                          title="Some of this verdict rests on an unverified fact, which scored 0"
                        >
                          Provisional
                        </Tag>
                      ) : (
                        <Tag variant="verified" title="Every rule behind this verdict cites a checked source">
                          Verified
                        </Tag>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>

        {!loading && emptyState ? (
          <div
            data-testid="empty-state"
            data-empty-kind={emptyState.kind}
            className="mx-auto max-w-md px-4 py-16 text-center"
          >
            <p className="text-xs font-medium text-ink-dim">{emptyState.title}</p>
            <p className="mt-1.5 text-2xs leading-relaxed text-ink-faint">
              {emptyState.detail}
            </p>
            {emptyState.action === "clear-filters" ? (
              <button
                type="button"
                onClick={onClearFilters}
                className="mt-3 border border-line bg-panel px-2.5 py-1 text-2xs text-ink-dim transition-colors hover:border-ink-faint hover:text-ink"
              >
                Clear filters
              </button>
            ) : null}
          </div>
        ) : null}
      </div>
    </section>
  );
}
