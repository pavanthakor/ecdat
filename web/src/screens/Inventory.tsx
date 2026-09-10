/**
 * INVENTORY -- every artefact in the scan, as stored, with a drill-down.
 *
 * The open artefact lives in the URL (`#/inventory?ref=<bom-ref>`), so a
 * finding link from any other screen lands on its drawer, and the top-bar
 * search lands here as `?q=`. Fix results for the drawer come from
 * `GET /scans/{id}/fixes`; a failure there is reported in the drawer, never
 * rendered as "no fix".
 */
import { Download } from "lucide-react";
import { useMemo, useState } from "react";

import { getFixes } from "@/api/client";
import { ArtefactDrawer, type FixLookup } from "@/components/ArtefactDrawer";
import { InventoryTable } from "@/components/InventoryTable";
import { Button, ScreenHeader } from "@/components/Panel";
import { navigate } from "@/lib/router";
import {
  applyFilters,
  NO_FILTERS,
  sortArtefacts,
  type Filters,
  type ScanView,
  type Sort,
  type SortColumn,
} from "@/state/inventory";
import { inventoryCsv } from "@/state/metrics";
import { emptyStateOf } from "@/state/presentation";
import { useRemote } from "@/state/remote";

export function downloadText(filename: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

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

  const fixes = useRemote(scanId && selected ? `fixes:${scanId}` : null, () =>
    getFixes(scanId as string),
  );
  const fixLookup: FixLookup = fixes.loading
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
        title="Inventory"
        subtitle="Every cryptographic artefact in this scan, exactly as the policy engine stored it. Select a row for its evidence, fired rules, drift and fix."
        actions={
          <Button
            disabled={!view.scan || view.artefacts.length === 0}
            onClick={() =>
              view.scan &&
              downloadText(
                `qorbit-inventory-${view.scan.id.slice(0, 8)}.csv`,
                inventoryCsv(sortArtefacts(view.artefacts, sort)),
                "text/csv",
              )
            }
          >
            <Download className="h-3 w-3" aria-hidden /> CSV
          </Button>
        }
      />
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
      />
      <ArtefactDrawer
        artefact={selected}
        onClose={() => navigate("inventory", params())}
        fixLookup={fixLookup}
      />
    </div>
  );
}
