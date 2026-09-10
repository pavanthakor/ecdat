/**
 * CRYPTOGRAPHIC DRIFT -- Declared -> Shipped -> Observed, one relationship card
 * per disagreement, laid out as web/design/ has it (ADR-0032): three view boxes
 * with DIVERGES/OBSERVED captions, a DRIFT DETECTED callout with its cause,
 * confidence and next check, then a per-view summary.
 *
 * Every box says what it knows: the STATED value, the value it DIVERGES with,
 * "not compared by this rule", or "not collected in this scan". Verified vs
 * provisional is the box's border -- a partial observation (confidence 50%) is
 * dashed. With fewer than two views collected the screen says drift CANNOT BE
 * ASSESSED, never "no drift": one view cannot disagree with itself (ADR-0012).
 * Colour stays semantic: diverging values are not painted red (ADR-0031).
 */
import type { LucideIcon } from "lucide-react";
import { AlertCircle, ArrowRight, Container, FileCode, ListFilter, Network } from "lucide-react";
import { useMemo } from "react";

import type { Artefact, ScanSummary, View } from "@/api/types";
import { VIEWS } from "@/api/types";
import { EmptyPanel } from "@/components/Honest";
import { ScreenHeader, SkeletonBlock, Tag } from "@/components/Panel";
import { cn, pad2, shortRef } from "@/lib/format";
import { hrefFor } from "@/lib/router";
import { collectedViews, driftPanelsOf, type DriftCell, type DriftPanel } from "@/state/metrics";

const SOURCE: Record<View, { label: string; Icon: LucideIcon }> = {
  declared: { label: "Declared config", Icon: FileCode },
  shipped: { label: "Container image", Icon: Container },
  observed: { label: "Runtime endpoint", Icon: Network },
};

/** The sighting a drift cites for one view: `view|locator` -> locator. */
function locatorFor(panel: DriftPanel, view: View): string | null {
  const hit = panel.evidence.find((entry) => entry.startsWith(`${view}|`));
  return hit ? hit.slice(view.length + 1) : null;
}

function ViewBox({ cell, locator }: { cell: DriftCell; locator: string | null }) {
  const speaks = cell.role === "stated" || cell.role === "compared";
  const dashed = !speaks || cell.provenance === "provisional";
  const { label, Icon } = SOURCE[cell.view];
  return (
    <div
      data-testid={`view-${cell.view}`}
      data-role={cell.role}
      className={cn(
        "min-w-0 rounded-md p-4",
        dashed ? "border border-dashed border-ink-faint/50" : "border border-line bg-raised/40",
      )}
    >
      <div className="eyebrow">{cell.view}</div>
      <div className="mt-2.5 flex items-center gap-2 font-mono text-[12.5px] text-ink">
        <Icon className="h-4 w-4 shrink-0 text-ink-dim" aria-hidden />
        {label}
      </div>
      {cell.value !== null ? (
        <div className="mt-2 break-words text-[14px] font-medium text-ink">{cell.value}</div>
      ) : (
        <div className="mt-2 text-[12px] text-ink-faint">
          {cell.role === "not-collected" ? "not collected in this scan" : "not compared by this rule"}
        </div>
      )}
      {speaks && locator ? (
        <div className="mt-3 truncate font-mono text-[11px] text-ink-faint" title={locator}>
          {locator}
        </div>
      ) : null}
      {cell.provenance ? (
        <div className="mt-2">
          <Tag variant={cell.provenance}>{cell.provenance === "verified" ? "Verified" : "Provisional"}</Tag>
        </div>
      ) : null}
    </div>
  );
}

function Arrow({ caption }: { caption: string | null }) {
  return (
    <div className="flex flex-col items-center justify-center gap-1.5 px-1 text-ink-dim" aria-hidden>
      <ArrowRight className="h-4 w-4" />
      <span className="h-3 font-mono text-[9px] uppercase tracking-wider text-ink-faint">{caption ?? ""}</span>
    </div>
  );
}

function FindingCard({ panel, index }: { panel: DriftPanel; index: number }) {
  const { artefact, cells, confidence } = panel;
  return (
    <section data-testid="drift-panel" className="rounded-lg border border-line bg-panel p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="eyebrow">
            Relationship analysis / finding {pad2(index + 1)} · {panel.kind}
          </div>
          <h2 className="mt-1 text-[15px] font-semibold text-ink">Declared → Shipped → Observed</h2>
          <a
            href={hrefFor("inventory", { ref: artefact.bomRef })}
            className="mt-1 inline-flex items-baseline gap-2 text-[12px] text-ink-dim hover:text-ink"
          >
            {artefact.name}
            <span className="font-mono text-[10.5px] text-ink-faint">{shortRef(artefact.bomRef)}</span>
          </a>
        </div>
        <div className="flex items-center gap-1.5">
          <Tag variant="verified">Verified</Tag>
          <Tag variant="provisional">Provisional</Tag>
        </div>
      </div>

      <div className="mt-5 grid grid-cols-[1fr_auto_1fr_auto_1fr] items-stretch gap-2">
        <ViewBox cell={cells.declared} locator={locatorFor(panel, "declared")} />
        <Arrow caption={panel.comparedView === "shipped" ? "Diverges" : null} />
        <ViewBox cell={cells.shipped} locator={locatorFor(panel, "shipped")} />
        <Arrow caption={panel.comparedView === "observed" ? "Diverges · observed" : null} />
        <ViewBox cell={cells.observed} locator={locatorFor(panel, "observed")} />
      </div>

      <div className="mt-5 grid gap-4 lg:grid-cols-[1.7fr_1fr]">
        <div className="rounded-md border border-line border-l-2 border-l-ink-dim bg-raised/40 px-4 py-3">
          <div className="flex items-center gap-2 text-[11.5px] font-semibold uppercase tracking-wider text-ink">
            <AlertCircle className="h-4 w-4" aria-hidden /> Drift detected
          </div>
          <p className="mt-2 text-[13px] leading-relaxed text-ink">{panel.cause}</p>
          <div className="mt-3 flex flex-wrap gap-1.5">
            <Tag>{panel.kind}</Tag>
            {panel.peers.map((peer) => (
              <Tag key={peer}>seen by {peer}</Tag>
            ))}
            <Tag>
              {panel.evidence.length} sighting{panel.evidence.length === 1 ? "" : "s"}
            </Tag>
          </div>
        </div>
        <div className="min-w-0">
          <div className="eyebrow">Confidence &amp; next check</div>
          <div className="mt-2 flex items-end justify-between gap-3">
            <span className="text-[32px] font-light leading-none tabular-nums text-ink">
              {confidence === null ? "—" : `${confidence}%`}
            </span>
            <span data-testid="next-check" className="text-right text-[11.5px] leading-snug text-ink-faint">
              {confidence === null ? "confidence not recorded" : "correlator confidence"}
              <br />
              next check: not scheduled — re-scan to re-check
            </span>
          </div>
          {confidence !== null ? (
            <div className="mt-3 h-1.5 rounded-full bg-line">
              <div className="h-full rounded-full bg-ink/80" style={{ width: `${confidence}%` }} />
            </div>
          ) : null}
        </div>
      </div>
    </section>
  );
}

function ViewSummary({
  view,
  artefacts,
  panels,
  collected,
}: {
  view: View;
  artefacts: Artefact[];
  panels: DriftPanel[];
  collected: View[];
}) {
  const isCollected = collected.includes(view);
  const unconfirmed = panels.some(
    (p) => p.cells[view].role === "compared" && p.cells[view].provenance === "provisional",
  );
  const count = artefacts.filter((a) => a.views.includes(view)).length;
  const solid = isCollected && !unconfirmed;
  return (
    <div className={cn("rounded-lg p-5", solid ? "border border-line bg-panel" : "border border-dashed border-line")}>
      <div className="eyebrow">{view}</div>
      <div className="mt-2 text-[20px] font-medium text-ink">
        {isCollected ? `${count} artefact${count === 1 ? "" : "s"}` : "Not collected"}
      </div>
      <div className="mt-1 text-[12px] text-ink-faint">{SOURCE[view].label}</div>
      <div className="mt-4">
        <Tag variant={solid ? "verified" : "provisional"}>
          {!isCollected ? "Not collected" : unconfirmed ? "Provisional" : "Collected"}
        </Tag>
      </div>
    </div>
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
  const waiting = loading && artefacts.length === 0;

  let body: React.ReactNode;
  if (waiting) {
    body = <SkeletonBlock className="h-64 w-full" />;
  } else if (!scan) {
    body = <EmptyPanel title="No scan selected" />;
  } else if (collected.length < 2) {
    body = (
      <EmptyPanel testId="drift-empty" kind="not-assessable" title="Drift cannot be assessed for this scan">
        {collected.length === 0 ? "No view was collected. " : `Only the ${collected[0]} view was collected. `}
        The {missing.join(" and ")} {missing.length === 1 ? "view was" : "views were"} not collected,
        and drift needs at least two views to compare. A view nobody looked at is a coverage gap,
        never a clean result. To collect them, scan a system manifest that adds an image target and
        an eBPF spool.
      </EmptyPanel>
    );
  } else if (panels.length === 0) {
    body = (
      <EmptyPanel testId="drift-empty" kind="none" title="No drift found">
        {collected.join(", ")} were collected, and they agree on every correlated artefact.
      </EmptyPanel>
    );
  } else {
    body = panels.map((panel, index) => <FindingCard key={panel.key} panel={panel} index={index} />);
  }

  return (
    <div>
      <ScreenHeader
        title="Cryptographic Drift"
        subtitle="Trace disagreements between declared policy, shipped code and observed endpoints — each with its cause, its evidence and the correlator's confidence."
        actions={
          scan ? (
            <span className="inline-flex items-center gap-1.5 rounded-md border border-line px-3 py-1.5 text-[13px] font-medium text-ink">
              <ListFilter className="h-3.5 w-3.5" aria-hidden />
              {panels.length} active signal{panels.length === 1 ? "" : "s"}
            </span>
          ) : undefined
        }
      />
      <div className="space-y-4 px-6 pb-6">
        {body}
        {scan && !waiting ? (
          <div className="grid gap-4 md:grid-cols-3">
            {VIEWS.map((view) => (
              <ViewSummary key={view} view={view} artefacts={artefacts} panels={panels} collected={collected} />
            ))}
          </div>
        ) : null}
      </div>
    </div>
  );
}
