/**
 * INVENTORY -- every artefact in the scan, as stored, with a drill-down;
 * rebuilt on the v2 mockup (inventory.html; ADR-0039): the filter bar, four
 * stat cards, then the artefact table with Export CSV in its head.
 *
 * The open artefact lives in the URL (`#/inventory?ref=<bom-ref>`), so a
 * finding link from any other screen lands on its drawer, and the topline
 * search lands here as `?q=`. Fix results for the drawer come from
 * `GET /scans/{id}/fixes`; a failure there is reported in the drawer, never
 * rendered as "no fix".
 *
 * The stat cards are counted from the loaded document. The mockup's deltas
 * ("+2") are not reproduced -- nothing computes them -- and "Drifted" says
 * "not computed" when fewer than two views were collected, because one view
 * cannot disagree with itself. The mockup's "Deadline < 2028" is a real count
 * against a stated cutoff: two years from now.
 */
import { AlertTriangle, CalendarClock, Download, GitCompareArrows, Table2 } from "lucide-react";
import { useMemo, useState } from "react";

import { getFixes } from "@/api/client";
import { ArtefactDrawer, type FixLookup } from "@/components/ArtefactDrawer";
import { MetricCard } from "@/components/Honest";
import { InventoryTable } from "@/components/InventoryTable";
import { ScreenHeader } from "@/components/Panel";
import { downloadText } from "@/lib/download";
import { navigate } from "@/lib/router";
import { canAdmin, NEEDS_ADMIN, useAuth } from "@/state/auth";
import { certaintyCountsOf } from "@/state/certainty";
import {
  applyFilters,
  NO_FILTERS,
  sortArtefacts,
  type Filters,
  type ScanView,
  type Sort,
  type SortColumn,
} from "@/state/inventory";
import { collectedViews, computed, inventoryCsv, notComputed, type Measured } from "@/state/metrics";
import { emptyStateOf } from "@/state/presentation";
import { useRemote } from "@/state/remote";

export function InventoryScreen({
  view,
  filters,
  onFilters,
  selectedRef,
}: {
  view: ScanView;
  filters: Filters;
  onFilters: (filters: Filters) => void;
  selectedRef: string | null;
}) {
  const [sort, setSort] = useState<Sort>({ column: "score", direction: "desc" });
  const scanId = view.scan?.id ?? null;

  const rows = useMemo(
    () => sortArtefacts(applyFilters(view.artefacts, filters), sort),
    [view.artefacts, filters, sort],
  );
  const emptyState = useMemo(
    () => emptyStateOf({ scan: view.scan, total: view.artefacts.length, shown: rows.length }),
    [view.scan, view.artefacts.length, rows.length],
  );
  const selected = useMemo(
    () => (selectedRef ? (view.artefacts.find((a) => a.bomRef === selectedRef) ?? null) : null),
    [selectedRef, view.artefacts],
  );
  const driftCount = useMemo(() => view.artefacts.filter((a) => a.drift.length > 0).length, [view.artefacts]);
  const certainty = useMemo(() => certaintyCountsOf(view.artefacts), [view.artefacts]);
  const collected = useMemo(() => collectedViews(view.artefacts), [view.artefacts]);

  // Fix results are served to an admin key only (ADR-0035): a viewer's drawer
  // says so, rather than asking for them and rendering the 403.
  const admin = canAdmin(useAuth().principal);
  const fixes = useRemote(admin && scanId && selected ? `fixes:${scanId}` : null, () =>
    getFixes(scanId as string),
  );
  const fixLookup: FixLookup = !admin
    ? { status: "error", message: NEEDS_ADMIN }
    : fixes.loading
      ? { status: "loading" }
      : fixes.error
        ? { status: "error", message: fixes.error }
        : { status: "loaded", entry: fixes.data?.fixes.find((f) => f.bom_ref === selectedRef) ?? null };

  const params = (ref?: string): Record<string, string> => {
    const next: Record<string, string> = {};
    if (filters.query) next.q = filters.query;
    if (ref) next.ref = ref;
    return next;
  };

  function onSort(column: SortColumn) {
    setSort((current) =>
      current.column === column
        ? { column, direction: current.direction === "desc" ? "asc" : "desc" }
        : { column, direction: column === "name" ? "asc" : "desc" },
    );
  }

  // The four cards, off the whole loaded document (not the filtered rows).
  const total = view.artefacts.length;
  const severe = view.artefacts.filter((a) => a.band === "Critical" || a.band === "High").length;
  const cutoff = new Date().getUTCFullYear() + 2;
  const dated = view.artefacts.filter((a) => a.deadline !== null);
  const soon = dated.filter((a) => Number.parseInt(a.deadline!.slice(0, 4), 10) <= cutoff);
  const drifted: Measured<number> =
    collected.length < 2
      ? notComputed(
          collected.length === 0
            ? "no view was collected, and drift needs two"
            : `only the ${collected[0]} view was collected, and drift needs two`,
        )
      : computed(driftCount, `${driftCount} artefact(s) whose views disagree`);
  const pct = (n: number) => (total === 0 ? 0 : Math.round((n / total) * 100));
  const icon = "h-[13px] w-[13px]";

  const stats = view.scan ? (
    <div className="stat-row of4 in" style={{ animationDelay: "0.06s" }}>
      <MetricCard
        id="inv-total"
        label="Total artefacts"
        icon={<Table2 className={icon} />}
        measured={computed(total, "every artefact in the stored document")}
        note="this scan"
      />
      <MetricCard
        id="inv-severe"
        label="Critical / high"
        icon={<AlertTriangle className={icon} />}
        measured={computed(severe, `${pct(severe)}% of the inventory scores Critical or High`)}
        note={`${pct(severe)}%`}
      />
      <MetricCard
        id="inv-drifted"
        label="Drifted"
        icon={<GitCompareArrows className={icon} />}
        measured={drifted}
        note="artefacts"
      />
      <MetricCard
        id="inv-deadline"
        label={`Deadline ≤ ${cutoff}`}
        icon={<CalendarClock className={icon} />}
        measured={computed(
          soon.length,
          `${soon.length} of ${dated.length} dated artefacts are due by the end of ${cutoff}; ${total - dated.length} carry no deadline`,
        )}
        note={`of ${dated.length} dated`}
      />
    </div>
  ) : null;

  return (
    <div className="content">
      <ScreenHeader
        title="Cryptographic Inventory"
        subtitle="Every cryptographic artefact discovered, with declared / shipped / observed provenance — exactly as the policy engine stored it."
      />
      <InventoryTable
        rows={rows}
        total={total}
        sort={sort}
        filters={filters}
        selected={selected?.bomRef ?? null}
        loading={view.loading}
        emptyState={emptyState}
        onSort={onSort}
        onFilters={onFilters}
        onSelect={(artefact) => navigate("inventory", params(artefact.bomRef))}
        onClearFilters={() => {
          onFilters(NO_FILTERS);
          navigate("inventory");
        }}
        driftCount={driftCount}
        candidateCount={certainty.candidate}
        confirmedCount={total - certainty.candidate}
        caption={collected.length > 0 ? `${collected.join(", ")} collected` : undefined}
        between={stats}
        actions={
          <button
            type="button"
            className="btn-ghost"
            disabled={!view.scan || total === 0}
            title="CSV of the stored values, generated in the browser"
            onClick={() =>
              view.scan &&
              downloadText(
                `ecdat-inventory-${view.scan.id.slice(0, 8)}.csv`,
                inventoryCsv(sortArtefacts(view.artefacts, sort)),
                "text/csv",
              )
            }
          >
            Export CSV <Download className="h-3.5 w-3.5" aria-hidden />
          </button>
        }
      />
      <ArtefactDrawer artefact={selected} onClose={() => navigate("inventory", params())} fixLookup={fixLookup} />
    </div>
  );
}
