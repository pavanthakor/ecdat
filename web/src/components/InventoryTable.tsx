/**
 * The inventory, rebuilt on the v2 mockup (inventory.html; ADR-0039): the
 * filter bar, then whatever the screen puts between (its stat row), then the
 * "Artefact inventory" panel with the nine-column table.
 *
 * * **A severity rail on every row**, in the first cell, in the row's band
 *   colour -- an edge marker, never a row fill.
 * * **The artefact name is the strongest thing in its row**; the bom-ref has
 *   its own mono column, because it is an address, not a label.
 * * **Verified vs provisional is the View chip's border** -- solid or dashed --
 *   and the word "provisional" in the sub-line; never a colour (ADR-0018).
 * * **A candidate is marked in the same vocabulary** (ADR-0034): a finding its
 *   rule FLAGGED a candidate gets a dashed "candidate" tag, a lighter name and
 *   its confidence in the sub-line. A finding below 1.0 for another reason is
 *   real crypto and gets no mark here; its confidence is in the drawer. The
 *   rail and the band badge are untouched -- a Low candidate is still Low.
 * * The mockup's filter chips are real controls: search, band and view
 *   selects, a drift-only toggle and a candidates / confirmed pair. Its
 *   "Internet-facing" chip is not reproduced: exposure is recorded per scan,
 *   not per artefact, so there is nothing to filter on. The filter LOGIC lives
 *   in inventory.ts.
 */
import { ArrowDown, ArrowUp, ChevronDown, GitCompareArrows, Search } from "lucide-react";
import type { ReactNode } from "react";

import type { Artefact, Band, View } from "@/api/types";
import { BANDS, VIEWS } from "@/api/types";
import { cn, shortLocator, shortRef } from "@/lib/format";
import { certaintyOf, formatConfidence } from "@/state/certainty";
import type { CertaintyFilter, Filters, Sort, SortColumn } from "@/state/inventory";
import type { EmptyState } from "@/state/presentation";
import { SkeletonRows } from "./Skeleton";
import { PanelHead, Prov, tone } from "./v2";

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
  /** The filter bar can be left out by a screen that does not want it. */
  filtersOpen?: boolean;
  /** Artefacts with drift in the whole scan, shown on the drift toggle. */
  driftCount?: number;
  /** Candidates and confirmed findings in the whole scan, shown on their toggles. */
  candidateCount?: number;
  confirmedCount?: number;
  /** A short fact appended to the row count, e.g. which views were collected. */
  caption?: string;
  /** Rendered between the filter bar and the table panel: the screen's stat row. */
  between?: ReactNode;
  /** The panel head's own control, e.g. Export CSV. */
  actions?: ReactNode;
}

/** The marker the candidate treatment uses, drawn small: a dashed box. */
const CANDIDATE_SWATCH = "h-2 w-3 shrink-0 rounded-[2px] border border-dashed border-ink-faint";
/** Its confirmed counterpart: solid, like a verified fact. */
const CONFIRMED_SWATCH = "h-2 w-3 shrink-0 rounded-[2px] border border-ink-dim";

const COLUMNS: { key: string; label: string; sort?: SortColumn; align?: "right" }[] = [
  { key: "name", label: "Artefact", sort: "name" },
  { key: "bom", label: "BOM ref" },
  { key: "view", label: "View", sort: "view" },
  { key: "band", label: "Band", sort: "band" },
  { key: "score", label: "Score", sort: "score", align: "right" },
  { key: "usage", label: "Usage", sort: "usage" },
  { key: "endpoint", label: "Endpoint", sort: "endpoint" },
  { key: "deadline", label: "Deadline", sort: "deadline" },
  { key: "drift", label: "Drift" },
];

function Legend() {
  return (
    <span className="hidden items-center gap-3 text-[10px] font-semibold uppercase tracking-wider text-ink-faint xl:flex">
      <span className="flex items-center gap-1.5">
        <span className="h-2 w-3 rounded-[2px] border border-ink-dim" aria-hidden /> Verified
      </span>
      <span className="flex items-center gap-1.5">
        <span className="h-2 w-3 rounded-[2px] border border-dashed border-ink-faint" aria-hidden /> Provisional
      </span>
      <span
        data-testid="legend-candidate"
        className="flex items-center gap-1.5"
        title="Flagged a candidate (ADR-0034): might not be real key material, shown for review"
      >
        <span className={CANDIDATE_SWATCH} aria-hidden /> Candidate
      </span>
    </span>
  );
}

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
  between,
  actions,
}: Props) {
  const band = filters.bands.length === 1 ? filters.bands[0] : "";
  const view = filters.views.length === 1 ? filters.views[0] : "";

  /** The two certainty toggles are exclusive, and pressing the active one clears it. */
  const toggleCertainty = (value: Exclude<CertaintyFilter, "all">) =>
    onFilters({ ...filters, certainty: filters.certainty === value ? "all" : value });

  return (
    <>
      {filtersOpen ? (
        <div className="filter-bar in">
          <label className="filter-search">
            <Search className="h-3.5 w-3.5 shrink-0" aria-hidden />
            <input
              value={filters.query}
              onChange={(e) => onFilters({ ...filters, query: e.target.value })}
              placeholder="Search artefacts, BOM refs, evidence…"
              aria-label="Filter artefacts"
            />
          </label>
          <span className="chip-select">
            <select
              aria-label="Band"
              value={band}
              onChange={(e) => onFilters({ ...filters, bands: e.target.value ? [e.target.value as Band] : [] })}
              className={cn("filter-chip", band && "active")}
            >
              <option value="">All bands</option>
              {BANDS.map((b) => (
                <option key={b} value={b}>
                  {b}
                </option>
              ))}
            </select>
            <ChevronDown className="h-3 w-3" aria-hidden />
          </span>
          <span className="chip-select">
            <select
              aria-label="View"
              value={view}
              onChange={(e) => onFilters({ ...filters, views: e.target.value ? [e.target.value as View] : [] })}
              className={cn("filter-chip", view && "active")}
            >
              <option value="">All views</option>
              {VIEWS.map((v) => (
                <option key={v} value={v}>
                  {v}
                </option>
              ))}
            </select>
            <ChevronDown className="h-3 w-3" aria-hidden />
          </span>
          <button
            type="button"
            aria-pressed={filters.driftOnly}
            onClick={() => onFilters({ ...filters, driftOnly: !filters.driftOnly })}
            className="filter-chip"
          >
            <GitCompareArrows className="h-3.5 w-3.5" aria-hidden />
            Drift only
            {driftCount !== undefined ? <span className="count">{driftCount}</span> : null}
          </button>
          <div role="group" aria-label="Certainty" className="flex items-center gap-2">
            <button
              type="button"
              aria-pressed={filters.certainty === "candidates"}
              onClick={() => toggleCertainty("candidates")}
              title="Findings flagged as candidates (ADR-0034): a key-ish name holding a high-entropy literal not seen reaching a crypto sink"
              className="filter-chip"
            >
              <span className={CANDIDATE_SWATCH} aria-hidden />
              Candidates
              {candidateCount !== undefined ? <span className="count">{candidateCount}</span> : null}
            </button>
            <button
              type="button"
              aria-pressed={filters.certainty === "confirmed"}
              onClick={() => toggleCertainty("confirmed")}
              title="Everything not flagged a candidate: findings at 1.0 and inferred ones (one detail not read outright). The drawer shows each finding's confidence."
              className="filter-chip"
            >
              <span className={CONFIRMED_SWATCH} aria-hidden />
              Confirmed
              {confirmedCount !== undefined ? <span className="count">{confirmedCount}</span> : null}
            </button>
          </div>
        </div>
      ) : null}

      {between}

      <section className="panel in" style={{ animationDelay: "0.1s" }}>
        <PanelHead
          title="Artefact inventory"
          sub={
            <span className="tabular-nums">
              {rows.length} of {total} artefacts{caption ? ` · ${caption}` : ""}
            </span>
          }
          right={
            <div className="flex shrink-0 items-center gap-4">
              <Legend />
              {actions}
            </div>
          }
        />

        <div className="overflow-x-auto">
          <table className="queue-table">
            <thead>
              <tr>
                {COLUMNS.map((column) => {
                  const active = column.sort !== undefined && sort.column === column.sort;
                  return (
                    <th key={column.key} className={column.align === "right" ? "text-right" : undefined}>
                      {column.sort ? (
                        <button
                          type="button"
                          onClick={() => onSort(column.sort as SortColumn)}
                          className={cn(
                            "inline-flex items-center gap-1 transition-colors",
                            active ? "text-ink" : "hover:text-ink-dim",
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
                        column.label
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
                      aria-selected={artefact.bomRef === selected}
                    >
                      <td>
                        <div className="flex items-center gap-3">
                          <span
                            data-testid="severity-bar"
                            data-band={artefact.band}
                            className={`sev-rail band-bg-${tone(artefact.band)}`}
                            aria-hidden
                          />
                          <div className="min-w-0">
                            <div className="flex items-center gap-1.5">
                              <span
                                data-testid="artefact-name"
                                className={cn(
                                  "qt-mono truncate",
                                  // Weight, not colour: a candidate never reads as the
                                  // strongest thing in its row.
                                  isCandidate ? "font-medium text-ink-dim" : "font-semibold text-ink",
                                )}
                              >
                                {artefact.name}
                              </span>
                              {isCandidate ? (
                                <span
                                  data-testid="candidate-tag"
                                  className="mark candidate border-dashed"
                                  title={`Candidate: confidence ${formatConfidence(artefact.confidence)}. Shown for review, not a confirmed finding (ADR-0034).`}
                                >
                                  candidate
                                </span>
                              ) : null}
                            </div>
                            <div className="qt-sub truncate">
                              {artefact.primitive ?? artefact.assetType}
                              {artefact.provisional ? " · provisional" : ""}
                              {isCandidate ? ` · confidence ${formatConfidence(artefact.confidence)}` : ""}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="qt-mono whitespace-nowrap text-[11px] text-ink-faint" title={artefact.bomRef}>
                        bom-ref: {shortRef(artefact.bomRef, 12)}
                      </td>
                      <td>
                        <Prov
                          kind={artefact.provisional ? "provisional" : "verified"}
                          title={
                            artefact.provisional
                              ? "Provisional: part of this verdict rests on an unverified fact, which scored 0"
                              : "Verified: every rule behind this verdict cites a checked source"
                          }
                        >
                          {artefact.view}
                        </Prov>
                      </td>
                      <td>
                        <span
                          data-testid="band-pill"
                          data-band={artefact.band}
                          className={`badge badge-${tone(artefact.band)}`}
                        >
                          {artefact.band}
                        </span>
                      </td>
                      <td className="qt-mono text-right tabular-nums">{artefact.score}</td>
                      <td className="whitespace-nowrap text-ink-dim">{artefact.usage}</td>
                      <td>
                        <span
                          className="qt-mono block max-w-[15rem] truncate text-[11.5px]"
                          title={artefact.endpoint ? "endpoint" : "first sighting — no endpoint recorded"}
                        >
                          {location}
                        </span>
                      </td>
                      <td>
                        <span
                          className={cn(
                            "qt-mono text-[11.5px] tabular-nums",
                            artefact.deadlineProvisional && "text-ink-faint line-through decoration-dotted",
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
                      <td>
                        {artefact.drift.length > 0 ? (
                          <span className="mark">Drift{artefact.drift.length > 1 ? ` ×${artefact.drift.length}` : ""}</span>
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
        </div>

        {!loading && emptyState ? (
          <div data-testid="empty-state" data-empty-kind={emptyState.kind} className="empty-state mt-4">
            <p className="empty-title">{emptyState.title}</p>
            <p className="empty-text">{emptyState.detail}</p>
            {emptyState.action === "clear-filters" ? (
              <button type="button" onClick={onClearFilters} className="btn-ghost">
                Clear filters
              </button>
            ) : null}
          </div>
        ) : null}
      </section>
    </>
  );
}
