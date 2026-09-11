/**
 * INVENTORY -- every artefact in the scan, as stored, with a drill-down.
 *
 * The open artefact lives in the URL (`#/inventory?ref=<bom-ref>`), so a
 * finding link from any other screen lands on its drawer, and the top-bar
 * search lands here as `?q=`. Fix results for the drawer come from
 * `GET /scans/{id}/fixes`; a failure there is reported in the drawer, never
 * rendered as "no fix".
 */
import { Download, Filter } from "lucide-react";
import { useMemo, useState } from "react";

import { getFixes } from "@/api/client";
import { ArtefactDrawer, type FixLookup } from "@/components/ArtefactDrawer";
import { InventoryTable } from "@/components/InventoryTable";
import { Button, ScreenHeader } from "@/components/Panel";
import { downloadText } from "@/lib/download";
import { navigate } from "@/lib/router";
import { canAdmin, NEEDS_ADMIN, useAuth } from "@/state/auth";
import {
  applyFilters,
  NO_FILTERS,
  sortArtefacts,
  type Filters,
  type ScanView,
  type Sort,
  type SortColumn,
} from "@/state/inventory";
import { certaintyCountsOf } from "@/state/certainty";
import { collectedViews, inventoryCsv } from "@/state/metrics";
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
  const [filtersOpen, setFiltersOpen] = useState(true);
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

  return (
    <div className="flex h-full min-h-0 flex-col">
      <ScreenHeader
        title="Cryptographic Inventory"
        subtitle="Artefacts discovered across the declared, shipped and observed layers, exactly as the policy engine stored them."
        actions={
          <>
            <Button aria-pressed={filtersOpen} onClick={() => setFiltersOpen((open) => !open)}>
              <Filter className="h-3.5 w-3.5" aria-hidden /> Filters
            </Button>
            <Button
              variant="primary"
              disabled={!view.scan || view.artefacts.length === 0}
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
              <Download className="h-3.5 w-3.5" aria-hidden /> Export
            </Button>
          </>
        }
      />
      <div className="flex min-h-0 flex-1 flex-col px-6 pb-6">
        <InventoryTable
          rows={rows}
          total={view.artefacts.length}
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
          filtersOpen={filtersOpen}
          driftCount={driftCount}
          candidateCount={certainty.candidate}
          confirmedCount={view.artefacts.length - certainty.candidate}
          caption={collected.length > 0 ? `${collected.join(", ")} collected` : undefined}
        />
      </div>
      <ArtefactDrawer
        artefact={selected}
        onClose={() => navigate("inventory", params())}
        fixLookup={fixLookup}
      />
    </div>
  );
}
