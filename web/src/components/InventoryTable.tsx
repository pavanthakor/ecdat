/**
 * The inventory table, laid out as web/design/ has it (ADR-0032).
 *
 * * **A severity bar on every row**, inset in the first cell, in the row's band
 *   colour -- an edge marker, never a row fill, so the row keeps its own
 *   background and the eye can run down the left margin.
 * * **The artefact name is the strongest thing in its row**; the bom-ref has
 *   its own mono column, because it is an address, not a label.
 * * **Verified vs provisional is a shape**, not a colour: a filled dot or a
 *   dashed ring beside the name, and the word "provisional" in the sub-line --
 *   a caveat that needs a hover is a caveat that will be missed (ADR-0018).
 * * **A candidate is marked in the same vocabulary** (ADR-0034): a finding its
 *   rule FLAGGED a candidate -- one that might not be real key material -- gets
 *   a dashed "candidate" tag, a lighter name, and its confidence in the
 *   sub-line. A finding below 1.0 for another reason (a parameter through a
 *   variable, a binary heuristic) is real crypto and gets no mark here; its
 *   confidence is in the drawer. The severity bar and the band pill are
 *   untouched -- a Low candidate is still Low.
 * * The filter bar is one search plus band and view selects, a drift-only
 *   toggle, and a candidates / confirmed pair; the filter LOGIC lives in
 *   inventory.ts.
 */
import { ArrowDown, ArrowUp, GitCompareArrows, ListFilter, Search } from "lucide-react";

import type { Artefact, Band, View } from "@/api/types";
import { BANDS, VIEWS } from "@/api/types";
import { BAND_STYLE, cn, shortLocator, shortRef } from "@/lib/format";
import { certaintyOf, formatConfidence } from "@/state/certainty";
import type { CertaintyFilter, Filters, Sort, SortColumn } from "@/state/inventory";
import type { EmptyState } from "@/state/presentation";
import { BandBadge, Tag } from "./Panel";
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
  /** The filter bar can be folded away by the screen's "Filters" button. */
  filtersOpen?: boolean;
  /** Artefacts with drift in the whole scan, shown on the drift toggle. */
  driftCount?: number;
  /** Candidates and confirmed findings in the whole scan, shown on their toggles. */
  candidateCount?: number;
  confirmedCount?: number;
  /** A short fact appended to the row count, e.g. which views were collected. */
  caption?: string;
}

const SELECT =
  "h-10 rounded-md border border-line bg-ground px-3 text-[13px] text-ink focus:border-ink-faint focus:outline-none";

const TOGGLE = "flex h-10 items-center gap-2 rounded-md border px-3 text-[13px] transition-colors";
const TOGGLE_ON = "border-ink-dim bg-raised text-ink";
const TOGGLE_OFF = "border-line text-ink-dim hover:text-ink";

/** The marker the candidate treatment uses, drawn small: a dashed box. */
const CANDIDATE_SWATCH = "h-2 w-3 shrink-0 rounded-[2px] border border-dashed border-ink-faint";
/** Its confirmed counterpart: solid, like a verified fact. */
const CONFIRMED_SWATCH = "h-2 w-3 shrink-0 rounded-[2px] border border-ink-dim";

const COLUMNS: {
  key: string;
  label: string;
  sort?: SortColumn;
  className?: string;
}[] = [
  { key: "name", label: "Artefact", sort: "name", className: "w-[19%]" },
  { key: "bom", label: "BOM ref", className: "w-[15%]" },
  { key: "view", label: "View", sort: "view", className: "w-[8%]" },
  { key: "band", label: "Band", sort: "band", className: "w-[8%]" },
  { key: "score", label: "Score", sort: "score", className: "w-[6%]" },
  { key: "usage", label: "Usage", sort: "usage", className: "w-[10%]" },
  { key: "endpoint", label: "Endpoint", sort: "endpoint", className: "w-[17%]" },
  { key: "deadline", label: "Deadline", sort: "deadline", className: "w-[9%]" },
  { key: "drift", label: "Drift", className: "w-[8%]" },
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
  filtersOpen = true,
  driftCount,
  candidateCount,
  confirmedCount,
  caption,
}: Props) {
  const band = filters.bands.length === 1 ? filters.bands[0] : "";
  const view = filters.views.length === 1 ? filters.views[0] : "";

  /** The two certainty toggles are exclusive, and pressing the active one clears it. */
  const toggleCertainty = (value: Exclude<CertaintyFilter, "all">) =>
    onFilters({ ...filters, certainty: filters.certainty === value ? "all" : value });

  return (
    <section className="flex min-h-0 flex-1 flex-col rounded-lg border border-line bg-panel">
      {filtersOpen ? (
        <div className="flex flex-wrap items-center gap-2 border-b border-line p-4">
          <label className="relative flex min-w-[16rem] flex-1 items-center">
            <Search className="pointer-events-none absolute left-3 h-4 w-4 text-ink-faint" aria-hidden />
            <input
              value={filters.query}
              onChange={(e) => onFilters({ ...filters, query: e.target.value })}
              placeholder="Search artefacts, BOM refs, evidence…"
              aria-label="Filter artefacts"
              className={cn(SELECT, "w-full pl-10 placeholder:text-ink-faint")}
            />
          </label>
          <select
            aria-label="Band"
            value={band}
            onChange={(e) => onFilters({ ...filters, bands: e.target.value ? [e.target.value as Band] : [] })}
            className={SELECT}
          >
            <option value="">All bands</option>
            {BANDS.map((b) => (
              <option key={b} value={b}>
                {b}
              </option>
            ))}
          </select>
          <select
            aria-label="View"
            value={view}
            onChange={(e) => onFilters({ ...filters, views: e.target.value ? [e.target.value as View] : [] })}
            className={SELECT}
          >
            <option value="">All views</option>
            {VIEWS.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
          <button
            type="button"
            aria-pressed={filters.driftOnly}
            onClick={() => onFilters({ ...filters, driftOnly: !filters.driftOnly })}
            className={cn(TOGGLE, filters.driftOnly ? TOGGLE_ON : TOGGLE_OFF)}
          >
            <GitCompareArrows className="h-4 w-4" aria-hidden />
            Drift only
            {driftCount !== undefined ? <span className="text-ink-faint">{driftCount}</span> : null}
          </button>
          <div role="group" aria-label="Certainty" className="flex items-center gap-2">
            <button
              type="button"
              aria-pressed={filters.certainty === "candidates"}
              onClick={() => toggleCertainty("candidates")}
              title="Findings flagged as candidates (ADR-0034): a key-ish name holding a high-entropy literal not seen reaching a crypto sink"
              className={cn(TOGGLE, filters.certainty === "candidates" ? TOGGLE_ON : TOGGLE_OFF)}
            >
              <span className={CANDIDATE_SWATCH} aria-hidden />
              Candidates
              {candidateCount !== undefined ? <span className="text-ink-faint">{candidateCount}</span> : null}
            </button>
            <button
              type="button"
              aria-pressed={filters.certainty === "confirmed"}
              onClick={() => toggleCertainty("confirmed")}
              title="Findings at confidence 1.0. An inferred finding (below 1.0, one detail not read outright) is in neither toggle."
              className={cn(TOGGLE, filters.certainty === "confirmed" ? TOGGLE_ON : TOGGLE_OFF)}
            >
              <span className={CONFIRMED_SWATCH} aria-hidden />
              Confirmed
              {confirmedCount !== undefined ? <span className="text-ink-faint">{confirmedCount}</span> : null}
            </button>
          </div>
        </div>
      ) : null}

      <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-3 text-[11.5px] text-ink-faint">
        <span className="flex items-center gap-2">
          <ListFilter className="h-3.5 w-3.5" aria-hidden />
          <span className="tabular-nums">
            {rows.length} of {total} artefacts
          </span>
          {caption ? <span>· {caption}</span> : null}
        </span>
        <span className="flex items-center gap-4 font-mono text-[10px] uppercase tracking-wider">
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-ink-dim" aria-hidden /> Verified
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full border border-dashed border-ink-faint" aria-hidden /> Provisional
          </span>
          <span
            data-testid="legend-candidate"
            className="flex items-center gap-1.5"
            title="Flagged a candidate (ADR-0034): might not be real key material, shown for review"
          >
            <span className={CANDIDATE_SWATCH} aria-hidden /> Candidate
          </span>
        </span>
      </div>

      <div className="mx-4 mb-4 min-h-0 flex-1 overflow-auto rounded-md border border-line">
        <table className="w-full border-collapse text-[13px]">
          <thead className="sticky top-0 z-10 bg-raised">
            <tr>
              {COLUMNS.map((column) => {
                const active = column.sort !== undefined && sort.column === column.sort;
                return (
                  <th
                    key={column.key}
                    className={cn("border-b border-line px-3 py-2.5 text-left font-semibold", column.className)}
                  >
                    {column.sort ? (
                      <button
                        type="button"
                        onClick={() => onSort(column.sort as SortColumn)}
                        className={cn(
                          "inline-flex items-center gap-1 text-[10px] uppercase tracking-[0.12em] transition-colors",
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
                      <span className="text-[10px] uppercase tracking-[0.12em] text-ink-faint">{column.label}</span>
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
                const certainty = certaintyOf(artefact);
                const isCandidate = certainty === "candidate";
                const location =
                  artefact.endpoint ??
                  (artefact.occurrences[0] ? shortLocator(artefact.occurrences[0].locator) : "—");
                return (
                  <tr
                    key={artefact.bomRef}
                    onClick={() => onSelect(artefact)}
                    data-ref={artefact.bomRef}
                    data-band={artefact.band}
                    data-certainty={certainty}
                    className={cn(
                      "cursor-pointer border-b border-line-soft transition-colors last:border-b-0",
                      isSelected ? "bg-raised" : "hover:bg-raised/50",
                    )}
                  >
                    <td className="px-3 py-2.5">
                      <div className="flex items-center gap-3">
                        <span
                          data-testid="severity-bar"
                          className={cn("h-9 w-[3px] shrink-0 rounded-full", BAND_STYLE[artefact.band].dot)}
                          aria-hidden
                        />
                        <div className="min-w-0">
                          <div className="flex items-center gap-1.5">
                            <span
                              data-testid="artefact-name"
                              className={cn(
                                "truncate",
                                // Weight, not colour: a candidate never reads as the
                                // strongest thing in its row.
                                isCandidate ? "font-medium text-ink-dim" : "font-semibold text-ink",
                              )}
                            >
                              {artefact.name}
                            </span>
                            <span
                              title={
                                artefact.provisional
                                  ? "Provisional: part of this verdict rests on an unverified fact, which scored 0"
                                  : "Verified: every rule behind this verdict cites a checked source"
                              }
                              className={cn(
                                "h-1.5 w-1.5 shrink-0 rounded-full",
                                artefact.provisional ? "border border-dashed border-ink-faint" : "bg-ink-dim",
                              )}
                            />
                            {isCandidate ? (
                              <Tag
                                variant="provisional"
                                testId="candidate-tag"
                                title={`Candidate: confidence ${formatConfidence(artefact.confidence)}. Shown for review, not a confirmed finding (ADR-0034).`}
                              >
                                candidate
                              </Tag>
                            ) : null}
                          </div>
                          <div className="truncate text-[11px] text-ink-faint">
                            {artefact.primitive ?? artefact.assetType}
                            {artefact.provisional ? " · provisional" : ""}
                            {isCandidate ? ` · confidence ${formatConfidence(artefact.confidence)}` : ""}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="px-3 py-2.5 font-mono text-[11px] text-ink-dim" title={artefact.bomRef}>
                      bom-ref: {shortRef(artefact.bomRef, 12)}
                    </td>
                    <td className="px-3 py-2.5">
                      <Tag>{artefact.view}</Tag>
                    </td>
                    <td className="px-3 py-2.5">
                      <BandBadge band={artefact.band} />
                    </td>
                    <td className="px-3 py-2.5 font-mono tabular-nums text-ink">{artefact.score}</td>
                    <td className="px-3 py-2.5 text-ink-dim">{artefact.usage}</td>
                    <td className="px-3 py-2.5">
                      <span
                        className="block truncate font-mono text-[11px] text-ink-dim"
                        title={artefact.endpoint ? "endpoint" : "first sighting — no endpoint recorded"}
                      >
                        {location}
                      </span>
                    </td>
                    <td className="px-3 py-2.5">
                      <span
                        className={cn(
                          "font-mono text-[11px] tabular-nums",
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
                    <td className="px-3 py-2.5">
                      {artefact.drift.length > 0 ? (
                        <Tag variant="strong">
                          Drift{artefact.drift.length > 1 ? ` ×${artefact.drift.length}` : ""}
                        </Tag>
                      ) : (
                        <span className="text-ink-faint">—</span>
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
            <p className="text-[13px] font-medium text-ink-dim">{emptyState.title}</p>
            <p className="mt-1.5 text-[12px] leading-relaxed text-ink-faint">{emptyState.detail}</p>
            {emptyState.action === "clear-filters" ? (
              <button
                type="button"
                onClick={onClearFilters}
                className="mt-3 rounded-md border border-line bg-panel px-3 py-1.5 text-[12px] text-ink-dim transition-colors hover:border-ink-faint hover:text-ink"
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
