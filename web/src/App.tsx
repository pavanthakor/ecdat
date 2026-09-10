/**
 * The console shell.
 *
 * One screen, four bands: a top bar that says WHICH estate, a summary strip
 * that says HOW BAD, the Mosca control, and the inventory. The slider sits
 * between the summary and the table because it changes both — in a sidebar it
 * would hide the cause of the thing it moves.
 */
import { useMemo, useState } from "react";

import type { Artefact } from "@/api/types";
import { BANDS } from "@/api/types";
import { ArtefactDrawer } from "@/components/ArtefactDrawer";
import { InfoTip } from "@/components/InfoTip";
import { InventoryTable } from "@/components/InventoryTable";
import { SummaryStrip } from "@/components/SummaryStrip";
import { Slider } from "@/components/ui/slider";
import { BAND_STYLE, cn, formatDate } from "@/lib/format";
import {
  NO_FILTERS,
  Z_MAX,
  Z_MIN,
  applyFilters,
  sortArtefacts,
  useScanView,
  type Filters,
  type Sort,
  type SortColumn,
} from "@/state/inventory";
import { bandCountsOf, emptyStateOf, engineLine } from "@/state/presentation";

const MOSCA_EXPLAINER =
  "Mosca's inequality: if the years data must stay secret (x) plus the years " +
  "migration takes (y) exceed the years until a cryptographically relevant " +
  "quantum computer (z), data encrypted today is already exposed. Moving z " +
  "re-scores the stored inventory; nothing is re-scanned.";

/** Quiet context, not an alert. Muted label, slightly less muted value. */
function MetaChip({ label, value }: { label: string; value: string | null }) {
  return (
    <span className="flex items-baseline gap-1.5 whitespace-nowrap">
      <span className="text-2xs uppercase tracking-wider text-ink-faint">
        {label}
      </span>
      <span className="font-mono text-2xs text-ink-dim">{value ?? "—"}</span>
    </span>
  );
}

export default function App() {
  const view = useScanView();
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);
  const [sort, setSort] = useState<Sort>({ column: "score", direction: "desc" });
  const [selected, setSelected] = useState<Artefact | null>(null);

  const rows = useMemo(
    () => sortArtefacts(applyFilters(view.artefacts, filters), sort),
    [view.artefacts, filters, sort],
  );

  // Recomputed from what is ON SCREEN, so it tracks the slider. Reading
  // scan.band_counts would freeze these numbers at the stored horizon while
  // the table beneath them changed.
  const live = useMemo(() => bandCountsOf(view.artefacts), [view.artefacts]);

  const emptyState = useMemo(
    () =>
      emptyStateOf({
        scan: view.scan,
        total: view.artefacts.length,
        shown: rows.length,
      }),
    [view.scan, view.artefacts.length, rows.length],
  );

  const footer = useMemo(
    () => (view.scan ? engineLine(view.scan, view.artefacts) : null),
    [view.scan, view.artefacts],
  );

  // Keep the drawer in step with a rescore: the artefact it shows is a
  // snapshot, and after a rescore the same bom-ref carries a new score.
  const openArtefact = useMemo(
    () =>
      selected
        ? (view.artefacts.find((a) => a.bomRef === selected.bomRef) ?? selected)
        : null,
    [selected, view.artefacts],
  );

  function onSort(column: SortColumn) {
    setSort((current) =>
      current.column === column
        ? { column, direction: current.direction === "desc" ? "asc" : "desc" }
        : { column, direction: column === "name" ? "asc" : "desc" },
    );
  }

  return (
    <div className="flex h-full flex-col bg-ground">
      <header className="flex items-center gap-5 border-b border-line bg-panel px-4 py-2">
        <span className="text-sm font-semibold tracking-tight text-ink">ECDAT</span>

        <div className="flex min-w-0 items-center gap-2">
          <label
            htmlFor="scan-select"
            className="text-2xs uppercase tracking-wider text-ink-faint"
          >
            Scan
          </label>
          <select
            id="scan-select"
            value={view.scan?.id ?? ""}
            onChange={(e) => view.selectScan(e.target.value)}
            className={cn(
              "h-7 max-w-md border border-line bg-ground px-2 font-mono text-2xs text-ink-dim",
              "focus:border-ink-faint focus:outline-none",
            )}
          >
            {view.scans.map((scan) => (
              <option key={scan.id} value={scan.id}>
                {scan.target.system ?? scan.target.ref} · {scan.kind} ·{" "}
                {formatDate(scan.created_at)} · {scan.id.slice(0, 8)}
              </option>
            ))}
          </select>
        </div>

        <div className="ml-auto flex items-center gap-5">
          <MetaChip label="sector" value={view.scan?.sector ?? null} />
          <MetaChip label="exposure" value={view.scan?.exposure ?? null} />
          <MetaChip label="data" value={view.scan?.target.data_class ?? null} />
        </div>
      </header>

      {view.error ? (
        <div className="border-b border-critical/40 bg-critical/10 px-4 py-1.5 text-2xs text-critical">
          {view.error}
        </div>
      ) : null}

      <SummaryStrip scan={view.scan} artefacts={view.artefacts} />

      {/* The Mosca control. Changing Z re-scores the STORED document through
          POST /scans/{id}/rescore — nothing is re-scanned, and the result is a
          new linked row rather than an edit of this one (ADR-0016). */}
      <div className="flex flex-wrap items-center gap-x-8 gap-y-3 border-b border-line bg-panel px-4 py-3">
        <div className="flex items-baseline gap-2">
          <span className="text-2xs uppercase tracking-widest text-ink-faint">
            CRQC horizon
          </span>
          <InfoTip label={MOSCA_EXPLAINER} />
        </div>

        <div className="flex items-baseline gap-1.5">
          <span
            className={cn(
              "font-mono text-2xl leading-none tabular-nums transition-colors",
              view.rescoring ? "text-ink-dim" : "text-ink",
            )}
          >
            {view.zYears}
          </span>
          <span className="text-2xs text-ink-faint">years</span>
        </div>

        <div className="flex min-w-[14rem] max-w-sm flex-1 items-center gap-3">
          <span className="font-mono text-2xs tabular-nums text-ink-faint">
            {Z_MIN}
          </span>
          <Slider
            value={[view.zYears]}
            min={Z_MIN}
            max={Z_MAX}
            step={1}
            aria-label="Years until a cryptographically relevant quantum computer"
            onValueChange={([value]) => view.setZYears(value)}
            disabled={!view.scan}
          />
          <span className="font-mono text-2xs tabular-nums text-ink-faint">
            {Z_MAX}
          </span>
        </div>

        {/* The consequence, live. These change as the handle moves. */}
        <div
          data-testid="live-readout"
          className={cn(
            "flex items-center gap-4 transition-opacity",
            view.rescoring ? "opacity-40" : "opacity-100",
          )}
        >
          {BANDS.map((band) => (
            <span key={band} className="flex items-baseline gap-1.5">
              <span className={cn("h-2 w-2 self-center", BAND_STYLE[band].dot)} />
              <span
                data-testid={`live-${band}`}
                className={cn(
                  "font-mono text-base tabular-nums",
                  live[band] > 0 ? BAND_STYLE[band].text : "text-ink-faint",
                )}
              >
                {live[band]}
              </span>
              <span className="text-2xs text-ink-faint">{band}</span>
            </span>
          ))}
        </div>
      </div>

      <InventoryTable
        rows={rows}
        total={view.artefacts.length}
        sort={sort}
        filters={filters}
        selected={openArtefact?.bomRef ?? null}
        loading={view.loading}
        emptyState={emptyState}
        onSort={onSort}
        onFilters={setFilters}
        onSelect={setSelected}
        onClearFilters={() => setFilters(NO_FILTERS)}
      />

      {/* Quiet, auditable: what produced this view. */}
      <footer className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-line bg-panel px-4 py-1.5 text-[10px] text-ink-faint">
        {view.scan ? (
          <>
            <span className="font-mono">
              scanned {formatDate(view.scan.created_at)}
            </span>
            {footer?.parts.map((part) => (
              <span key={part} className="font-mono before:mr-3 before:content-['·']">
                {part}
              </span>
            ))}
            {footer?.warning ? (
              <span className="text-high" title={footer.warning}>
                · engine mismatch
              </span>
            ) : null}
          </>
        ) : null}
      </footer>

      <ArtefactDrawer artefact={openArtefact} onClose={() => setSelected(null)} />
    </div>
  );
}
