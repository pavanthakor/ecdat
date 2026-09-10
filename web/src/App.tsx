/**
 * The console shell.
 *
 * One screen, three bands: a top bar that says WHICH estate and WHEN, a
 * summary strip that says HOW BAD, and the inventory that says WHAT. The
 * Mosca slider sits between the summary and the table because it changes both
 * — putting it in a sidebar would hide the cause of the thing it moves.
 */
import { useMemo, useState } from "react";
import { Loader2, ShieldHalf, TriangleAlert } from "lucide-react";

import type { Artefact } from "@/api/types";
import { ArtefactDrawer } from "@/components/ArtefactDrawer";
import { InventoryTable } from "@/components/InventoryTable";
import { SummaryStrip } from "@/components/SummaryStrip";
import { Slider } from "@/components/ui/slider";
import { cn, formatDate } from "@/lib/format";
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

export default function App() {
  const view = useScanView();
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);
  const [sort, setSort] = useState<Sort>({ column: "score", direction: "desc" });
  const [selected, setSelected] = useState<Artefact | null>(null);

  const rows = useMemo(
    () => sortArtefacts(applyFilters(view.artefacts, filters), sort),
    [view.artefacts, filters, sort],
  );

  // Keep the drawer in step with a rescore: the artefact it is showing is a
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
      <header className="flex items-center gap-4 border-b border-line bg-panel px-4 py-2">
        <div className="flex items-center gap-2">
          <ShieldHalf className="h-4 w-4 text-accent" aria-hidden />
          <span className="text-sm font-semibold tracking-tight text-ink">ECDAT</span>
          <span className="hidden text-2xs text-ink-faint sm:inline">
            Cryptographic Discovery &amp; Analysis
          </span>
        </div>

        <div className="ml-4 flex min-w-0 items-center gap-2">
          <label
            htmlFor="scan-select"
            className="text-2xs uppercase tracking-widest text-ink-faint"
          >
            Scan
          </label>
          <select
            id="scan-select"
            value={view.scan?.id ?? ""}
            onChange={(e) => view.selectScan(e.target.value)}
            className={cn(
              "h-7 max-w-md border border-line bg-ground px-2 font-mono text-2xs text-ink",
              "focus:border-accent/60 focus:outline-none",
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

        <div className="ml-auto flex items-center gap-4 text-2xs text-ink-faint">
          {view.scan ? (
            <>
              <span>
                sector{" "}
                <span className="font-mono text-ink-dim">
                  {view.scan.sector ?? "—"}
                </span>
              </span>
              <span>
                exposure{" "}
                <span className="font-mono text-ink-dim">
                  {view.scan.exposure ?? "—"}
                </span>
              </span>
              <span>
                data{" "}
                <span className="font-mono text-ink-dim">
                  {view.scan.target.data_class ?? "—"}
                </span>
              </span>
            </>
          ) : null}
        </div>
      </header>

      {view.error ? (
        <div className="flex items-center gap-2 border-b border-critical/40 bg-critical/10 px-4 py-1.5 text-2xs text-critical">
          <TriangleAlert className="h-3 w-3" aria-hidden />
          {view.error}
        </div>
      ) : null}

      <SummaryStrip scan={view.scan} artefacts={view.artefacts} />

      {/* The Mosca slider. Changing Z re-scores the STORED document through
          POST /scans/{id}/rescore -- nothing is re-scanned, and the result is
          a new linked row rather than an edit of this one (ADR-0016). */}
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 border-b border-line bg-panel px-4 py-2.5">
        <div className="flex items-baseline gap-2">
          <span className="text-2xs uppercase tracking-widest text-ink-faint">
            CRQC horizon
          </span>
          <span className="font-mono text-2xl leading-none tabular-nums text-accent">
            {view.zYears}
          </span>
          <span className="text-2xs text-ink-faint">years</span>
        </div>

        <div className="flex min-w-[16rem] max-w-lg flex-1 items-center gap-3">
          <span className="font-mono text-2xs text-ink-faint">{Z_MIN}</span>
          <Slider
            value={[view.zYears]}
            min={Z_MIN}
            max={Z_MAX}
            step={1}
            aria-label="Years until a cryptographically relevant quantum computer"
            onValueChange={([value]) => view.setZYears(value)}
            disabled={!view.scan}
          />
          <span className="font-mono text-2xs text-ink-faint">{Z_MAX}</span>
        </div>

        <div className="flex items-center gap-2 text-2xs">
          {view.rescoring ? (
            <span className="flex items-center gap-1.5 text-accent">
              <Loader2 className="h-3 w-3 animate-spin" aria-hidden />
              re-scoring
            </span>
          ) : (
            <span className="text-ink-faint">
              Mosca: x + y &gt; z — pulling z in raises every urgency
            </span>
          )}
        </div>
      </div>

      {view.loading ? (
        <div className="flex flex-1 items-center justify-center text-xs text-ink-faint">
          <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />
          loading inventory…
        </div>
      ) : (
        <InventoryTable
          rows={rows}
          total={view.artefacts.length}
          sort={sort}
          filters={filters}
          selected={openArtefact?.bomRef ?? null}
          onSort={onSort}
          onFilters={setFilters}
          onSelect={setSelected}
        />
      )}

      <ArtefactDrawer artefact={openArtefact} onClose={() => setSelected(null)} />
    </div>
  );
}
