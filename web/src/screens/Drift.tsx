/**
 * CRYPTOGRAPHIC DRIFT -- Declared -> Shipped -> Observed, per disagreement.
 *
 * Each panel shows all three views side by side, and every cell says what it
 * knows: the STATED value, the value it DIVERGES with, "not compared by this
 * rule", or "not collected in this scan". Verified vs provisional is the
 * cell's border -- a partial observation (confidence 50%) is dashed.
 *
 * With fewer than two views collected, the screen says drift CANNOT BE
 * ASSESSED. It never says "no drift": one view cannot disagree with itself,
 * and a missing view is a coverage gap (ADR-0012).
 */
import { ArrowRight } from "lucide-react";
import { useMemo } from "react";

import type { Artefact, ScanSummary } from "@/api/types";
import { VIEWS } from "@/api/types";
import { EmptyPanel } from "@/components/Honest";
import { ScreenHeader, SkeletonBlock, Tag } from "@/components/Panel";
import { cn, shortRef } from "@/lib/format";
import { hrefFor } from "@/lib/router";
import { collectedViews, driftPanelsOf, type DriftCell, type DriftPanel } from "@/state/metrics";

function ViewCell({ cell }: { cell: DriftCell }) {
  const speaks = cell.role === "stated" || cell.role === "compared";
  return (
    <div
      data-testid={`view-${cell.view}`}
      data-role={cell.role}
      className={cn(
        "min-w-0 px-3 py-2",
        speaks
          ? cell.provenance === "provisional"
            ? "border border-dashed border-ink-faint/60"
            : "border border-line bg-raised"
          : "border border-dashed border-line/70",
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="eyebrow">{cell.view}</span>
        <span className="flex gap-1">
          {cell.role === "stated" ? <Tag>Stated</Tag> : null}
          {cell.role === "compared" ? <Tag variant="strong">Diverges</Tag> : null}
          {cell.role === "compared" && cell.view === "observed" ? <Tag>Observed</Tag> : null}
        </span>
      </div>
      {cell.value !== null ? (
        <div className="mt-1 break-words font-mono text-xs text-ink">{cell.value}</div>
      ) : (
        <div className="mt-1 text-2xs text-ink-faint">
          {cell.role === "not-collected" ? "not collected in this scan" : "not compared by this rule"}
        </div>
      )}
      {cell.provenance ? (
        <div className="mt-1.5">
          <Tag variant={cell.provenance}>
            {cell.provenance === "verified" ? "Verified" : "Provisional · unconfirmed"}
          </Tag>
        </div>
      ) : null}
    </div>
  );
}

function Connector() {
  return (
    <div className="flex items-center justify-center px-1 text-ink-faint" aria-hidden>
      <ArrowRight className="h-3.5 w-3.5" />
    </div>
  );
}

function DriftCard({ panel }: { panel: DriftPanel }) {
  const { artefact } = panel;
  return (
    <article
      data-testid="drift-panel"
      className={cn(
        "border border-line border-l-2 bg-panel",
        artefact.band === "Critical"
          ? "border-l-critical"
          : artefact.band === "High"
            ? "border-l-high"
            : "border-l-line",
      )}
    >
      <header className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b border-line px-3 py-2">
        <a
          href={hrefFor("inventory", { ref: artefact.bomRef })}
          className="text-sm font-medium text-ink hover:underline"
        >
          {artefact.name}
        </a>
        <span className="font-mono text-[10px] text-ink-faint">{shortRef(artefact.bomRef)}</span>
        <Tag>{panel.kind}</Tag>
        <span className="ml-auto font-mono text-2xs tabular-nums text-ink-dim">
          confidence {panel.confidence === null ? "not recorded" : `${panel.confidence}%`}
        </span>
      </header>

      <div className="grid grid-cols-[1fr_auto_1fr_auto_1fr] gap-y-2 px-3 py-3">
        <ViewCell cell={panel.cells.declared} />
        <Connector />
        <ViewCell cell={panel.cells.shipped} />
        <Connector />
        <ViewCell cell={panel.cells.observed} />
      </div>

      <div className="border-t border-line px-3 py-2">
        <div className="flex flex-wrap items-baseline gap-2">
          <Tag variant="strong">Drift detected</Tag>
          <p className="min-w-0 flex-1 text-2xs leading-relaxed text-ink-dim">{panel.cause}</p>
        </div>
        <div className="mt-2 grid gap-3 text-2xs sm:grid-cols-3">
          <div className="min-w-0">
            <div className="eyebrow">Evidence</div>
            <ul className="mt-0.5 space-y-0.5">
              {panel.evidence.map((entry) => (
                <li key={entry} className="truncate font-mono text-[10px] text-ink-faint" title={entry}>
                  {entry}
                </li>
              ))}
            </ul>
          </div>
          <div>
            <div className="eyebrow">Seen by</div>
            <div className="mt-0.5 font-mono text-[10px] text-ink-dim">
              {panel.peers.length > 0 ? panel.peers.join(", ") : "—"}
            </div>
          </div>
          <div data-testid="next-check">
            <div className="eyebrow">Next check</div>
            <div className="mt-0.5 text-[10px] text-ink-faint">
              not scheduled — ECDAT runs no monitoring job; re-scan to re-check
            </div>
          </div>
        </div>
      </div>
    </article>
  );
}

export function DriftScreen({
  artefacts,
  scan,
  loading,
}: {
  artefacts: Artefact[];
  scan: ScanSummary | null;
  loading: boolean;
}) {
  const panels = useMemo(() => driftPanelsOf(artefacts), [artefacts]);
  const collected = useMemo(() => collectedViews(artefacts), [artefacts]);
  const missing = VIEWS.filter((v) => !collected.includes(v));
  const kinds = useMemo(() => {
    const counts = new Map<string, number>();
    for (const panel of panels) counts.set(panel.kind, (counts.get(panel.kind) ?? 0) + 1);
    return [...counts.entries()];
  }, [panels]);

  let body: React.ReactNode;
  if (loading && artefacts.length === 0) {
    body = <SkeletonBlock className="h-40 w-full" />;
  } else if (!scan) {
    body = <EmptyPanel title="No scan selected" />;
  } else if (collected.length < 2) {
    body = (
      <EmptyPanel
        testId="drift-empty"
        kind="not-assessable"
        title="Drift cannot be assessed for this scan"
      >
        {collected.length === 0
          ? "No view was collected. "
          : `Only the ${collected[0]} view was collected. `}
        The {missing.join(" and ")} {missing.length === 1 ? "view was" : "views were"} not
        collected, and drift needs at least two views to compare. A view nobody looked at
        is a coverage gap, never a clean result. To collect them, scan a system manifest
        that adds an image target and an eBPF spool.
      </EmptyPanel>
    );
  } else if (panels.length === 0) {
    body = (
      <EmptyPanel testId="drift-empty" kind="none" title="No drift found">
        {collected.join(", ")} were collected, and they agree on every correlated artefact.
      </EmptyPanel>
    );
  } else {
    body = panels.map((panel) => <DriftCard key={panel.key} panel={panel} />);
  }

  return (
    <div>
      <ScreenHeader
        title="Cryptographic Drift"
        subtitle="Where what was declared, what was shipped and what was observed disagree — each with its cause, its evidence and the correlator's confidence."
      />
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-line bg-panel px-5 py-2 text-2xs">
        <span className="text-ink-faint">Views collected</span>
        {VIEWS.map((v) => (
          <Tag key={v} variant={collected.includes(v) ? "verified" : "provisional"}>
            {v}
          </Tag>
        ))}
        <span className="ml-auto font-mono tabular-nums text-ink-dim">
          {panels.length} drift finding{panels.length === 1 ? "" : "s"}
        </span>
        {kinds.map(([kind, n]) => (
          <span key={kind} className="font-mono text-[10px] text-ink-faint">
            {kind} {n}
          </span>
        ))}
      </div>
      <div className="space-y-3 p-4">{body}</div>
    </div>
  );
}
