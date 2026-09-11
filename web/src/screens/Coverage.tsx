/**
 * COVERAGE -- "Scanner Coverage", the tool's honesty screen, rebuilt on the v2
 * mockup (coverage.html; ADR-0039): the coverage headline with a card per
 * scanner, then evidence-layer coverage.
 *
 * The mockup's cards say VERIFIED / PROVISIONAL / UNAVAILABLE with work counts
 * ("42 manifests indexed"); the row cannot support those. `scanners_ran`
 * records the OFFERED set (`scanner_records(scanners)`), so a repo scan lists
 * the binary scanner the orchestrator skipped, and a crash is logged, not
 * stored (PUNCHLIST). The status here is SELECTED / NOT RUN / UNKNOWN (ADR-0031
 * §4) as a solid / dashed / dotted chip, and the per-scanner attributed-artefact
 * count carries the real signal -- a sighting from a scanner proves it looked.
 *
 * The mockup's "86% · 124 of 144 expected artefacts" has no denominator ECDAT
 * knows; the headline is evidence-layer coverage, views collected of three.
 * Its TLS / SSH probe card is not drawn: no probe scanner exists (PUNCHLIST).
 */
import { CircleDashed, CircleDot, CircleHelp, ExternalLink } from "lucide-react";
import { useMemo } from "react";

import { listScanners, reportPath } from "@/api/client";
import type { Artefact, ScanSummary, View } from "@/api/types";
import { VIEWS } from "@/api/types";
import { FileButton } from "@/components/FileButton";
import { NotComputed } from "@/components/Honest";
import { ScreenHeader } from "@/components/Panel";
import { EmptyState, Notice, PanelHead, Prov, useGrown, type ProvKind } from "@/components/v2";
import { cn } from "@/lib/format";
import { SCANNER_VIEW, scannerCoverage, viewCoverage, type ScannerCard } from "@/state/metrics";
import { useRemote } from "@/state/remote";

/** What each view would have told us -- reports/coverage.py VIEW_MEANING. */
const VIEW_MEANING: Record<View, string> = {
  declared: "what the team says it uses — source, manifests, configuration",
  shipped: "what actually got built — container images, binaries, certificates",
  observed: "what a host was really doing — TLS handshakes seen at runtime",
};

/** How each view is collected -- reports/coverage.py VIEW_REMEDY. */
const VIEW_REMEDY: Record<View, string> = {
  declared: "add a repo or directory target to the system manifest",
  shipped: "add an image target (a docker save tar or OCI layout)",
  observed: "add a spool target — a directory the eBPF agent wrote",
};

const STATUS_ICON = {
  SELECTED: CircleDot,
  "NOT RUN": CircleDashed,
  UNKNOWN: CircleHelp,
} as const;

/** Solid for a recorded selection, dashed for not run, dotted for unknown. */
const STATUS_PROV: Record<ScannerCard["status"], ProvKind> = {
  SELECTED: "verified",
  "NOT RUN": "provisional",
  UNKNOWN: "unavailable",
};

const FOOTNOTE: Record<ScannerCard["status"], string> = {
  SELECTED:
    "offered to this scan; whether it applied to the target, ran or failed is in the server log, not on the row",
  "NOT RUN": "a view this scanner feeds may be missing as a result",
  UNKNOWN: "this row predates scanners_ran, so whether it ran cannot be established",
};

function subline(card: ScannerCard): string {
  if (card.status === "SELECTED") {
    return `${card.artefacts} artefact${card.artefacts === 1 ? "" : "s"} attributed${card.version ? ` · v${card.version}` : ""}`;
  }
  return card.status === "NOT RUN" ? "not selected for this scan" : "not recorded for this scan";
}

function ScannerTile({ card }: { card: ScannerCard }) {
  const Icon = STATUS_ICON[card.status];
  return (
    <article
      data-testid="scanner-card"
      data-status={card.status}
      className={cn("scanner-card", card.status === "NOT RUN" && "dashed", card.status === "UNKNOWN" && "dotted")}
    >
      <div className="scanner-name">
        <span>{card.label} Scanner</span>
        <Icon className="h-4 w-4" aria-hidden />
      </div>
      <div className="scanner-detail">
        {subline(card)} · feeds {SCANNER_VIEW[card.id] ?? "—"}
      </div>
      <div className="scanner-status flex flex-wrap gap-1.5">
        <Prov kind={STATUS_PROV[card.status]}>{card.status}</Prov>
        {card.status === "SELECTED" && card.provisional > 0 ? (
          <Prov kind="provisional">{card.provisional} provisional</Prov>
        ) : null}
        {card.engine === "UNAVAILABLE" ? <Prov kind="unavailable">engine unavailable</Prov> : null}
        {card.engine && card.engine !== "UNAVAILABLE" ? <span className="format-tag">engine {card.engine}</span> : null}
      </div>
      <p className="scanner-note">{FOOTNOTE[card.status]}</p>
    </article>
  );
}

export function CoverageScreen({
  scan,
  artefacts,
}: {
  scan: ScanSummary | null;
  artefacts: Artefact[];
}) {
  const scanners = useRemote("scanners", listScanners);
  const coverage = useMemo(() => viewCoverage(artefacts), [artefacts]);
  const cards = useMemo(
    () => (scan ? scannerCoverage(scan, scanners.data, artefacts) : []),
    [scan, scanners.data, artefacts],
  );
  const provisional = artefacts.filter((a) => a.provisional).length;
  const grown = useGrown();

  return (
    <div className="content">
      <ScreenHeader
        title="Scanner Coverage"
        subtitle="What ECDAT was able to observe, and where visibility is missing. A view nobody collected is not a view that came back clean, and a scanner that did not run found nothing because it did not look."
        actions={
          scan ? (
            <FileButton
              bare
              mode="view"
              className="btn-ghost"
              path={reportPath(scan.id, "coverage")}
              filename={`ecdat-coverage-${scan.id.slice(0, 8)}.pdf`}
            >
              <ExternalLink className="h-3.5 w-3.5" aria-hidden /> Coverage statement (PDF)
            </FileButton>
          ) : undefined
        }
      />
      {!scan ? (
        <EmptyState title="No scan selected" />
      ) : (
        <>
          <section className="panel in mb-3" data-testid="coverage-panel" style={{ animationDelay: "0.04s" }}>
            <PanelHead title="Coverage" sub="What ECDAT was able to observe, and where visibility is missing" />
            <div className="metric-hero mt-2">
              {coverage.share.status === "computed" ? (
                <span className="metric-hero-num lg" data-testid="coverage-share">
                  {coverage.share.value}%
                </span>
              ) : (
                <NotComputed reason={coverage.share.reason} />
              )}
              <div>
                <div className="metric-hero-tag">Evidence-layer coverage</div>
                <div className="metric-hero-note">
                  {coverage.collected.length} of 3 views collected
                  {coverage.collected.length > 0 ? ` (${coverage.collected.join(", ")})` : ""} · {artefacts.length}{" "}
                  artefacts attributed
                </div>
              </div>
            </div>
            {scanners.error ? (
              <div className="mt-3">
                <Notice>The server's scanner list could not be loaded — showing the scanners this row recorded.</Notice>
              </div>
            ) : null}
            <div className="scanner-grid">
              {cards.map((card) => (
                <ScannerTile key={card.id} card={card} />
              ))}
              <article data-testid="policy-card" className="scanner-card">
                <div className="scanner-name">
                  <span>Policy Engine</span>
                  <CircleDot className="h-4 w-4" aria-hidden />
                </div>
                <div className="scanner-detail">
                  {artefacts.length} artefacts scored · {provisional} with an unverified fact · scores every view
                </div>
                <div className="scanner-status flex flex-wrap gap-1.5">
                  {provisional > 0 ? (
                    <Prov kind="provisional">{provisional} provisional</Prov>
                  ) : (
                    <Prov kind="verified">Verified</Prov>
                  )}
                </div>
                <p className="scanner-note">
                  an unverified rule is listed but scores 0 (ADR-0017); packs applied are not exposed by the API
                </p>
              </article>
            </div>
          </section>

          <section className="panel in" data-testid="layer-panel" style={{ animationDelay: "0.1s" }}>
            <PanelHead
              title="Evidence layer coverage"
              sub="The gap between what's declared, what ships, and what's actually observed"
            />
            {VIEWS.map((name) => {
              const collected = coverage.collected.includes(name);
              const pulse = coverage.pulse[name];
              const inView = artefacts.filter((a) => a.views.includes(name)).length;
              return (
                <div key={name} data-testid={`matrix-${name}`} data-collected={collected}>
                  <div className="layer-row">
                    <div className="layer-label">{name}</div>
                    <div className={cn("layer-track", !collected && "absent")}>
                      {collected ? (
                        <div className="layer-fill" style={{ width: grown ? `${pulse.percent}%` : 0 }} />
                      ) : null}
                    </div>
                    <div className={cn("layer-pct", !collected && "absent")}>
                      {collected ? `${pulse.percent}%` : "Not collected"}
                    </div>
                  </div>
                  <div className="layer-note">
                    {collected
                      ? `${pulse.seen}/${pulse.total} sighted · ${inView} in this view — ${VIEW_MEANING[name]}`
                      : `${VIEW_MEANING[name]} — to collect it: ${VIEW_REMEDY[name]}`}
                  </div>
                </div>
              );
            })}
            <p className="page-sub mt-4">
              <span className="mono text-ink-dim">{scan.coverage_gaps}</span> component(s) were correlated against a
              group missing at least one view (from the scan row), so any drift verdict on them rests on fewer
              sightings than a complete group would give.
            </p>
          </section>
        </>
      )}
    </div>
  );
}
