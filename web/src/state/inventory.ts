/**
 * Inventory state: filtering, sorting, and the Mosca rescore round trip.
 *
 * Split out of the components on purpose. Filtering that quietly drops rows
 * and a rescore that leaves a stale table are both invisible in a screenshot
 * review, so they live here as testable functions and one hook rather than
 * inside JSX.
 */
import { useCallback, useEffect, useRef, useState } from "react";

import { getCbom, listScans, rescore } from "@/api/client";
import { parseCbom } from "@/api/parse";
import type { Artefact, Band, ScanSummary, View } from "@/api/types";

/** Severity order. Bands must never sort alphabetically -- Low would beat Medium. */
const BAND_RANK: Record<Band, number> = {
  Critical: 3,
  High: 2,
  Medium: 1,
  Low: 0,
};

export interface Filters {
  bands: Band[];
  views: (View | string)[];
  driftOnly: boolean;
  query: string;
}

export type SortColumn =
  | "name"
  | "view"
  | "band"
  | "score"
  | "usage"
  | "endpoint"
  | "deadline";

export interface Sort {
  column: SortColumn;
  direction: "asc" | "desc";
}

export const NO_FILTERS: Filters = {
  bands: [],
  views: [],
  driftOnly: false,
  query: "",
};

/** How long a Z-slider drag settles before a rescore is issued. */
export const RESCORE_DEBOUNCE_MS = 300;

/** The horizon range the slider offers. */
export const Z_MIN = 5;
export const Z_MAX = 20;
export const Z_DEFAULT = 11;

function matchesQuery(artefact: Artefact, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  const haystacks = [
    artefact.name,
    artefact.bomRef,
    artefact.endpoint ?? "",
    artefact.assetType,
    artefact.usage,
    ...artefact.occurrences.map((o) => o.locator),
    ...artefact.labels,
  ];
  return haystacks.some((h) => h.toLowerCase().includes(needle));
}

/**
 * Narrow the table.
 *
 * An empty selection means "no constraint on this axis", NOT "match nothing" --
 * but `driftOnly` is a boolean, so it constrains as soon as it is on. A
 * drift-only filter over a document with no drift therefore returns nothing,
 * which is the honest answer: "there is no drift here" and "the filter is
 * broken" must not look the same.
 */
export function applyFilters(artefacts: Artefact[], filters: Filters): Artefact[] {
  return artefacts.filter((artefact) => {
    if (filters.bands.length > 0 && !filters.bands.includes(artefact.band)) {
      return false;
    }
    if (filters.views.length > 0 && !filters.views.includes(artefact.view)) {
      return false;
    }
    if (filters.driftOnly && artefact.drift.length === 0) return false;
    return matchesQuery(artefact, filters.query);
  });
}

function compare(a: Artefact, b: Artefact, column: SortColumn): number {
  switch (column) {
    case "score":
      return a.score - b.score;
    case "band":
      return BAND_RANK[a.band] - BAND_RANK[b.band];
    case "deadline":
      // A component with no deadline sorts after every dated one, whichever
      // direction is asked for -- "no deadline" is not "the soonest deadline".
      return (a.deadline ?? "9999-12-31").localeCompare(b.deadline ?? "9999-12-31");
    case "endpoint":
      return (a.endpoint ?? "").localeCompare(b.endpoint ?? "");
    case "view":
      return a.view.localeCompare(b.view);
    case "usage":
      return a.usage.localeCompare(b.usage);
    default:
      return a.name.localeCompare(b.name);
  }
}

/**
 * Order the table.
 *
 * Ties break on name then bom-ref, so the order is TOTAL: two renders of the
 * same data put the same row in the same place, and a rescore that leaves
 * scores tied does not shuffle the table under the reader's cursor.
 */
export function sortArtefacts(artefacts: Artefact[], sort: Sort): Artefact[] {
  const factor = sort.direction === "asc" ? 1 : -1;
  return [...artefacts].sort((a, b) => {
    const primary = compare(a, b, sort.column) * factor;
    if (primary !== 0) return primary;
    const byName = a.name.localeCompare(b.name);
    return byName !== 0 ? byName : a.bomRef.localeCompare(b.bomRef);
  });
}

export interface ScanView {
  scans: ScanSummary[];
  scan: ScanSummary | null;
  artefacts: Artefact[];
  zYears: number;
  loading: boolean;
  rescoring: boolean;
  error: string | null;
  setZYears: (value: number) => void;
  selectScan: (scanId: string) => void;
  reload: () => void;
}

/**
 * Load a scan and re-score it live as the Z slider moves.
 *
 * Two decisions worth naming:
 *
 * **Rescores always derive from the ORIGINAL scan**, never from the previous
 * rescore row. Chaining would compound the pass and make the estate's score
 * depend on how many times somebody dragged the slider.
 *
 * **A failed rescore keeps the last good table.** Blanking the console on an
 * error would replace a true inventory at the old horizon with nothing at all;
 * the honest state is "here is what you had, and here is why it did not
 * move".
 */
export function useScanView(): ScanView {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [scan, setScan] = useState<ScanSummary | null>(null);
  const [artefacts, setArtefacts] = useState<Artefact[]>([]);
  const [zYears, setZ] = useState(Z_DEFAULT);
  const [loading, setLoading] = useState(true);
  const [rescoring, setRescoring] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Guards against a slow rescore landing after a faster later one and
  // overwriting it -- the table must always show the horizon last asked for.
  const generation = useRef(0);

  const load = useCallback(async (chosen?: string) => {
    setLoading(true);
    setError(null);
    try {
      const rows = await listScans();
      setScans(rows);
      const original = rows.filter((row) => row.kind === "scan");
      const picked =
        (chosen ? rows.find((row) => row.id === chosen) : undefined) ??
        original[0] ??
        rows[0] ??
        null;
      setScan(picked);
      if (picked) {
        setZ(picked.z_years ?? Z_DEFAULT);
        setArtefacts(parseCbom(await getCbom(picked.id)));
      } else {
        setArtefacts([]);
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const setZYears = useCallback(
    (value: number) => {
      // The label moves immediately; the request waits for the drag to settle.
      setZ(value);
      if (!scan) return;
      if (timer.current) clearTimeout(timer.current);

      const mine = ++generation.current;
      timer.current = setTimeout(() => {
        void (async () => {
          setRescoring(true);
          setError(null);
          try {
            const created = await rescore(scan.id, value);
            const document = await getCbom(created.scan_id);
            if (generation.current === mine) setArtefacts(parseCbom(document));
          } catch (cause) {
            if (generation.current === mine) {
              setError(cause instanceof Error ? cause.message : String(cause));
            }
          } finally {
            if (generation.current === mine) setRescoring(false);
          }
        })();
      }, RESCORE_DEBOUNCE_MS);
    },
    [scan],
  );

  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current);
    },
    [],
  );

  return {
    scans,
    scan,
    artefacts,
    zYears,
    loading,
    rescoring,
    error,
    setZYears,
    selectScan: (scanId: string) => void load(scanId),
    reload: () => void load(scan?.id),
  };
}
