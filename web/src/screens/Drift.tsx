/**
 * CRYPTOGRAPHIC DRIFT -- rebuilt on the v2 mockup (drift.html; ADR-0039): the
 * selected finding's evidence chain -- Declared → Shipped → Observed, then the
 * cause, the correlator's confidence and a Re-scan -- beside the list of every
 * drift finding on this scan, then evidence-layer coverage.
 *
 * Every node says what it knows: the STATED value, the value it DIVERGES with,
 * "not compared by this rule", or "not collected in this scan". Verified vs
 * provisional is the node's border and a chip, never a colour; the mockup's red
 * mismatch is a brighter border and the word "diverges" (ADR-0031). With fewer
 * than two views collected the screen says drift CANNOT BE ASSESSED, never "no
 * drift": one view cannot disagree with itself (ADR-0012).
 *
 * The mockup's "94% evidence confidence" is the correlator's own confidence on
 * the drift record, or "not recorded"; its cause tags are the drift kind, the
 * peers that saw it and the sighting count -- not invented categories.
 */
import type { LucideIcon } from "lucide-react";
import { AlertTriangle, ArrowRight, Container, FileCode, Network, RefreshCw } from "lucide-react";
import { useMemo, useState } from "react";

import type { Artefact, ScanSummary, View } from "@/api/types";
import { VIEWS } from "@/api/types";
import { ScreenHeader } from "@/components/Panel";
import { BandTag, EmptyState, Notice, PanelHead, Prov, useGrown } from "@/components/v2";
import { cn, pad2, shortLocator } from "@/lib/format";
import { hrefFor } from "@/lib/router";
import { canAdmin, NEEDS_ADMIN, useAuth } from "@/state/auth";
import { collectedViews, driftPanelsOf, viewCoverage, type DriftCell, type DriftPanel } from "@/state/metrics";
import { useRescan, type RescanState } from "@/state/rescan";

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

function placeOf(artefact: Artefact): string {
  return (
    artefact.endpoint ??
    (artefact.occurrences[0] ? shortLocator(artefact.occurrences[0].locator) : "no location recorded")
  );
}

function Node({ cell, locator }: { cell: DriftCell; locator: string | null }) {
  const speaks = cell.role === "stated" || cell.role === "compared";
  const { label, Icon } = SOURCE[cell.view];
  return (
    <div
      data-testid={`view-${cell.view}`}
      data-role={cell.role}
      className={cn(
        "drift-node",
        !speaks && "silent",
        cell.role === "compared" && "mismatch",
        cell.provenance === "provisional" && "provisional",
      )}
    >
      <div className="drift-node-label">{cell.view}</div>
      <div className="drift-node-kind flex items-center gap-1.5">
        <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden />
        {label}
      </div>
      {cell.value !== null ? (
        <div className="drift-node-value">{cell.value}</div>
      ) : (
        <div className="drift-node-value absent">
          {cell.role === "not-collected" ? "not collected in this scan" : "not compared by this rule"}
        </div>
      )}
      {speaks && locator ? (
        <div className="drift-node-ref" title={locator}>
          {locator}
        </div>
      ) : null}
      {cell.provenance ? (
        <Prov
          kind={cell.provenance}
          title={
            cell.provenance === "verified"
              ? "Confirmed by positive sightings"
              : "Backed by an absence, or a partial observation — not confirmed"
          }
        >
          {cell.provenance === "verified" ? "Verified" : "Provisional"}
        </Prov>
      ) : null}
    </div>
  );
}

function Arrow({ active }: { active: boolean }) {
  return (
    <div className={cn("drift-arrow", active && "active")} aria-hidden>
      <ArrowRight className="h-5 w-5" />
      <span className="h-3">{active ? "diverges" : ""}</span>
    </div>
  );
}

function DriftDetail({
  panel,
  index,
  total,
  canRescan,
  rescan,
  onRescan,
}: {
  panel: DriftPanel;
  index: number;
  total: number;
  canRescan: boolean;
  rescan: RescanState;
  onRescan: () => void;
}) {
  const { artefact, cells, confidence } = panel;
  const running = rescan.state === "running";
  return (
    <section className="panel in" data-testid="drift-panel" data-kind={panel.kind}>
      <PanelHead
        title={`${artefact.name} · ${panel.kind}`}
        sub={
          <>
            {placeOf(artefact)} — finding {pad2(index + 1)} of {pad2(total)}, traced across the evidence chain ·{" "}
            <a className="underline decoration-dotted hover:text-ink" href={hrefFor("inventory", { ref: artefact.bomRef })}>
              open in Inventory
            </a>
          </>
        }
        right={<BandTag band={artefact.band} />}
      />

      <div className="drift-chain">
        <Node cell={cells.declared} locator={locatorFor(panel, "declared")} />
        <Arrow active={panel.comparedView === "shipped"} />
        <Node cell={cells.shipped} locator={locatorFor(panel, "shipped")} />
        <Arrow active={panel.comparedView === "observed"} />
        <Node cell={cells.observed} locator={locatorFor(panel, "observed")} />
      </div>

      <div className="drift-detail">
        <div>
          <div className="drift-detail-title">
            <AlertTriangle className="h-3.5 w-3.5" aria-hidden /> Drift detected
          </div>
          <div className="drift-detail-text">{panel.cause}</div>
          <div className="cause-tags">
            <span className="cause-tag">{panel.kind}</span>
            {panel.peers.map((peer) => (
              <span key={peer} className="cause-tag">
                seen by {peer}
              </span>
            ))}
            <span className="cause-tag">
              {panel.evidence.length} sighting{panel.evidence.length === 1 ? "" : "s"}
            </span>
          </div>
        </div>
        <div className="confidence-block">
          <div className="confidence-num">{confidence === null ? "—" : `${confidence}%`}</div>
          <div className="confidence-label">
            {confidence === null ? "Confidence not recorded" : "Correlator confidence"}
          </div>
          {confidence !== null ? (
            <div className="confidence-track">
              <div className="confidence-fill" style={{ width: `${confidence}%` }} />
            </div>
          ) : null}
          <div data-testid="next-check" className="confidence-label mt-2">
            next check: not scheduled — re-scan to re-check
          </div>
          <div className="mt-3">
            <button
              type="button"
              className="btn-ghost"
              disabled={!canRescan || running}
              title={canRescan ? "Scan the same target again, e.g. after rebuilding what drifted" : NEEDS_ADMIN}
              onClick={onRescan}
            >
              <RefreshCw className="h-3.5 w-3.5" aria-hidden /> {running ? "Re-scanning…" : "Re-scan"}
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}

function FindingsList({
  panels,
  selected,
  onSelect,
}: {
  panels: DriftPanel[];
  selected: string | null;
  onSelect: (key: string) => void;
}) {
  return (
    <section className="panel in" data-testid="drift-findings" style={{ animationDelay: "0.06s" }}>
      <PanelHead
        title="Drift findings"
        sub={`This scan · ${panels.length} signal${panels.length === 1 ? "" : "s"}`}
      />
      <div className="overflow-x-auto">
        <table className="queue-table">
          <thead>
            <tr>
              <th>Artefact</th>
              <th>Band</th>
            </tr>
          </thead>
          <tbody>
            {panels.map((panel) => (
              <tr
                key={panel.key}
                data-testid="drift-row"
                data-band={panel.artefact.band}
                aria-selected={panel.key === selected}
                tabIndex={0}
                onClick={() => onSelect(panel.key)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onSelect(panel.key);
                  }
                }}
              >
                <td className="qt-mono font-bold">
                  {panel.artefact.name}
                  <div className="qt-sub max-w-[16rem] truncate" title={`${panel.kind} · ${placeOf(panel.artefact)}`}>
                    {panel.kind} · {placeOf(panel.artefact)}
                  </div>
                </td>
                <td>
                  <BandTag band={panel.artefact.band} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function LayerCoverage({ artefacts }: { artefacts: Artefact[] }) {
  const coverage = useMemo(() => viewCoverage(artefacts), [artefacts]);
  const grown = useGrown();
  return (
    <section className="panel in" data-testid="layer-coverage" style={{ animationDelay: "0.1s" }}>
      <PanelHead title="Evidence layer coverage" sub="Where drift can and cannot yet be confirmed" />
      {VIEWS.map((view) => {
        const collected = coverage.collected.includes(view);
        const pulse = coverage.pulse[view];
        return (
          <div key={view} className="layer-row" data-testid={`layer-${view}`} data-collected={collected}>
            <div className="layer-label">{view}</div>
            <div className={cn("layer-track", !collected && "absent")}>
              {collected ? <div className="layer-fill" style={{ width: grown ? `${pulse.percent}%` : 0 }} /> : null}
            </div>
            <div
              className={cn("layer-pct", !collected && "absent")}
              title={collected ? `${pulse.seen} of ${pulse.total} artefacts sighted in this view or its group` : undefined}
            >
              {collected ? `${pulse.percent}%` : "Not collected"}
            </div>
          </div>
        );
      })}
      <p className="page-sub mt-3">
        The share of artefacts sighted in each view or its correlation group. A view nobody collected is a
        coverage gap, never a clean result.
      </p>
    </section>
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
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const index = Math.max(
    0,
    panels.findIndex((panel) => panel.key === selectedKey),
  );
  const selected = panels[index] ?? null;
  const admin = canAdmin(useAuth().principal);
  const { rescan, start } = useRescan(scan);

  let body: React.ReactNode;
  if (waiting) {
    body = (
      <div className="grid-row grid-2-1">
        <div className="panel h-72 animate-pulse" />
        <div className="panel h-72 animate-pulse" />
      </div>
    );
  } else if (!scan) {
    body = <EmptyState title="No scan selected" />;
  } else if (collected.length < 2) {
    body = (
      <EmptyState testId="drift-empty" kind="not-assessable" title="Drift cannot be assessed for this scan">
        {collected.length === 0 ? "No view was collected. " : `Only the ${collected[0]} view was collected. `}
        The {missing.join(" and ")} {missing.length === 1 ? "view was" : "views were"} not collected, and drift
        needs at least two views to compare. A view nobody looked at is a coverage gap, never a clean result. To
        collect them, scan a system manifest that adds an image target and an eBPF spool.
      </EmptyState>
    );
  } else if (panels.length === 0 || !selected) {
    body = (
      <EmptyState testId="drift-empty" kind="none" title="No drift found">
        {collected.join(", ")} were collected, and they agree on every correlated artefact.
      </EmptyState>
    );
  } else {
    body = (
      <div className="grid-row grid-2-1">
        <DriftDetail
          panel={selected}
          index={index}
          total={panels.length}
          canRescan={admin && scan !== null}
          rescan={rescan}
          onRescan={() => void start()}
        />
        <FindingsList panels={panels} selected={selected.key} onSelect={setSelectedKey} />
      </div>
    );
  }

  return (
    <div className="content">
      <ScreenHeader
        title="Cryptographic Drift"
        subtitle="Trace disagreements between declared policy, shipped code and observed endpoints."
      />
      {rescan.message ? <Notice error={rescan.state === "error"}>{rescan.message}</Notice> : null}
      <div className="mb-3">{body}</div>
      {scan && !waiting ? <LayerCoverage artefacts={artefacts} /> : null}
    </div>
  );
}
