/**
 * COVERAGE -- "Scanner Coverage", the tool's honesty screen, laid out as
 * web/design/ has it (ADR-0032): large scanner cards on a three-column grid,
 * then the evidence-layer visibility matrix.
 *
 * The design's cards say COMPLETE / PARTIAL; the row cannot support either.
 * `scanners_ran` records the OFFERED set (`scanner_records(scanners)`), so a
 * repo scan lists the binary scanner the orchestrator skipped, and a crash is
 * logged, not stored (PUNCHLIST). The status here is SELECTED / NOT RUN /
 * UNKNOWN (ADR-0031 §4), and the per-scanner attributed-artefact count carries
 * the real signal -- a sighting from a scanner proves that scanner looked.
 */
import { CircleDashed, CircleDot, CircleHelp, ExternalLink } from "lucide-react";
import { useMemo } from "react";

import { listScanners, reportUrl } from "@/api/client";
import type { Artefact, ScanSummary, View } from "@/api/types";
import { VIEWS } from "@/api/types";
import { EmptyPanel } from "@/components/Honest";
import { LinkButton, Panel, ScreenHeader, Tag } from "@/components/Panel";
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
      className={cn(
        "rounded-lg p-5",
        card.status === "SELECTED" && "border border-line bg-panel",
        card.status === "NOT RUN" && "border border-dashed border-line",
        card.status === "UNKNOWN" && "border border-dotted border-ink-faint/60",
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="eyebrow">Scanner · feeds {SCANNER_VIEW[card.id] ?? "—"}</div>
          <h2 className="mt-1 text-[16px] font-semibold text-ink">{card.label} Scanner</h2>
        </div>
        <Icon className="h-5 w-5 shrink-0 text-ink-dim" aria-hidden />
      </div>
      <div className="mt-4 font-mono text-[13px] uppercase tracking-wider text-ink">{card.status}</div>
      <div className="mt-1 text-[12px] text-ink-faint">{subline(card)}</div>
      <div className="mt-4 flex min-h-[1.25rem] flex-wrap gap-1.5">
        {card.status === "SELECTED" && card.artefacts > 0 ? (
          card.provisional > 0 ? (
            <Tag variant="provisional">{card.provisional} provisional</Tag>
          ) : (
            <Tag variant="verified">Verified</Tag>
          )
        ) : null}
        {card.engine === "UNAVAILABLE" ? <Tag variant="provisional">Unavailable</Tag> : null}
        {card.engine && card.engine !== "UNAVAILABLE" ? <Tag>engine {card.engine}</Tag> : null}
      </div>
      <p className="mt-3 text-[11px] leading-snug text-ink-faint">{FOOTNOTE[card.status]}</p>
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

  return (
    <div>
      <ScreenHeader
        title="Scanner Coverage"
        subtitle="See what was inspected, what was not, and what remains unobserved. A view nobody collected is not a view that came back clean, and a scanner that did not run found nothing because it did not look."
        actions={
          scan ? (
            <LinkButton href={reportUrl(scan.id, "coverage")} target="_blank" rel="noopener">
              <ExternalLink className="h-3.5 w-3.5" aria-hidden /> Coverage statement (PDF)
            </LinkButton>
          ) : undefined
        }
      />
      {!scan ? (
        <div className="px-6 pb-6">
          <EmptyPanel title="No scan selected" />
        </div>
      ) : (
        <div className="space-y-4 px-6 pb-6">
          {scanners.error ? (
            <p className="text-[12px] text-ink-faint">
              The server's scanner list could not be loaded — showing the scanners this row recorded.
            </p>
          ) : null}
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {cards.map((card) => (
              <ScannerTile key={card.id} card={card} />
            ))}
            <article data-testid="policy-card" className="rounded-lg border border-line bg-panel p-5">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="eyebrow">Engine · scores every view</div>
                  <h2 className="mt-1 text-[16px] font-semibold text-ink">Policy Engine</h2>
                </div>
                <CircleDot className="h-5 w-5 shrink-0 text-ink-dim" aria-hidden />
              </div>
              <div className="mt-4 font-mono text-[13px] uppercase tracking-wider text-ink">Scored</div>
              <div className="mt-1 text-[12px] text-ink-faint">
                {artefacts.length} artefacts scored · {provisional} with an unverified fact
              </div>
              <div className="mt-4 flex min-h-[1.25rem] flex-wrap gap-1.5">
                {provisional > 0 ? (
                  <Tag variant="provisional">{provisional} provisional</Tag>
                ) : (
                  <Tag variant="verified">Verified</Tag>
                )}
              </div>
              <p className="mt-3 text-[11px] leading-snug text-ink-faint">
                an unverified rule is listed but scores 0 (ADR-0017); packs applied are not exposed by the API
              </p>
            </article>
          </div>

          <Panel eyebrow="Visibility matrix" title="Evidence layer coverage">
            <div className="grid overflow-hidden rounded-md border border-tint-line md:grid-cols-3">
              {VIEWS.map((name) => {
                const collected = coverage.collected.includes(name);
                const pulse = coverage.pulse[name];
                const inView = artefacts.filter((a) => a.views.includes(name)).length;
                return (
                  <div
                    key={name}
                    data-testid={`matrix-${name}`}
                    className={cn(
                      "border-tint-line p-5 md:border-l md:first:border-l-0",
                      collected ? "bg-tint" : "bg-transparent",
                    )}
                  >
                    <div className="eyebrow">{name}</div>
                    <div className="mt-2 text-[30px] font-light leading-none tabular-nums text-ink">
                      {collected ? `${pulse.percent}%` : <span className="text-[18px] text-ink-dim">Not collected</span>}
                    </div>
                    <div className="mt-2 text-[12px] text-ink-dim">{VIEW_MEANING[name]}</div>
                    <div className="mt-3 font-mono text-[11px] text-ink-faint">
                      {collected
                        ? `${pulse.seen}/${pulse.total} sighted · ${inView} in this view`
                        : `to collect it: ${VIEW_REMEDY[name]}`}
                    </div>
                  </div>
                );
              })}
            </div>
            <p className="mt-4 text-[12px] leading-relaxed text-ink-faint">
              <span className="font-mono tabular-nums text-ink-dim">{scan.coverage_gaps}</span> component(s)
              were correlated against a group missing at least one view (from the scan row), so any drift
              verdict on them rests on fewer sightings than a complete group would give.
            </p>
          </Panel>
        </div>
      )}
    </div>
  );
}
