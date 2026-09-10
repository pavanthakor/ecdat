/**
 * Presentation logic that has to be right, kept out of JSX so it can be
 * tested: the live band readout, the empty states, and the footer line.
 */
import type { Artefact, Band, ScanSummary } from "@/api/types";
import { BANDS } from "@/api/types";

/**
 * Band counts for the artefacts currently on screen.
 *
 * Deliberately NOT `scan.band_counts`. That row describes the horizon the scan
 * was stored at, and the entire point of the Mosca slider is that the estate
 * looks different at another one — reading the row would freeze the headline
 * numbers while the table beneath them changed, which is worse than showing
 * nothing at all.
 *
 * Every band is always present, zeroes included: a band that vanishes from the
 * readout reads as "not assessed" rather than "none".
 */
export function bandCountsOf(artefacts: Artefact[]): Record<Band, number> {
  const counts = Object.fromEntries(BANDS.map((band) => [band, 0])) as Record<
    Band,
    number
  >;
  for (const artefact of artefacts) counts[artefact.band] += 1;
  return counts;
}

export type EmptyStateKind = "no-scan" | "no-artefacts" | "filtered-out";

export interface EmptyState {
  kind: EmptyStateKind;
  title: string;
  detail: string;
  /** The one state a reader can act on from here. */
  action: "clear-filters" | null;
}

/**
 * Which nothing-to-show message applies.
 *
 * Three situations a single "no results" would collapse, and only one of them
 * has an action. Offering "clear filters" to somebody whose scan genuinely
 * found no cryptography sends them chasing a control that cannot help.
 */
export function emptyStateOf({
  scan,
  total,
  shown,
}: {
  scan: ScanSummary | null;
  total: number;
  shown: number;
}): EmptyState | null {
  if (shown > 0) return null;
  if (!scan) {
    return {
      kind: "no-scan",
      title: "No scan selected",
      detail: "Choose a scan from the selector above, or run one with `ecdat scan`.",
      action: null,
    };
  }
  if (total === 0) {
    return {
      kind: "no-artefacts",
      title: "This scan found no cryptographic artefacts",
      detail:
        "The scanners ran and reported nothing. Check the scanner coverage above — a view nobody looked at is not a view that came back clean.",
      action: null,
    };
  }
  return {
    kind: "filtered-out",
    title: "No artefact matches these filters",
    detail: `${total} artefacts in this scan are hidden by the current filters.`,
    action: "clear-filters",
  };
}

export interface EngineLine {
  parts: string[];
  warning: string | null;
}

/**
 * The footer: what produced this view, in one quiet line.
 *
 * A tool that can say which engine version reached a conclusion is a tool
 * somebody can audit. One that cannot is asking to be trusted.
 */
export function engineLine(scan: ScanSummary, artefacts: Artefact[] = []): EngineLine {
  const parts: string[] = [];
  const versions = scan.engine_versions;

  if (!versions) {
    parts.push("engine not recorded");
  } else {
    if (typeof versions.ecdat === "string") parts.push(`ECDAT ${versions.ecdat}`);
    for (const [id, value] of Object.entries(versions)) {
      if (id === "ecdat" || typeof value !== "object" || value === null) continue;
      const entry = value as { pinned?: string; installed?: string };
      const engine = id === "source" ? "semgrep" : id;
      const installed = entry.installed ?? "not installed";
      parts.push(
        entry.installed && entry.installed !== entry.pinned
          ? `${engine} ${installed} (pinned ${entry.pinned})`
          : `${engine} ${installed}`,
      );
    }
  }

  const provisional = artefacts.filter((a) => a.provisional).length;
  parts.push(`${provisional} facts provisional`);

  return { parts, warning: scan.engine_warning };
}
