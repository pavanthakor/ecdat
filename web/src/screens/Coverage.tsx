/**
 * COVERAGE -- the tool's honesty screen: what this scan looked at, and what it
 * did not.
 *
 * Scanner cards read `scanners_ran` three ways (ADR-0016): null = UNKNOWN,
 * listed = SELECTED, absent = NOT RUN. Never "ran": the row records the
 * OFFERED set (`scanner_records(scanners)`), so a repo scan lists the binary
 * scanner the orchestrator skipped, and a crash is logged, not stored
 * (PUNCHLIST). The per-scanner artefact count is the real signal -- an
 * attributed sighting proves that scanner looked. The visibility matrix
 * mirrors the coverage report's view table (reports/coverage.py).
 */
import { ExternalLink } from "lucide-react";
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

const FOOTNOTE: Record<ScannerCard["status"], string> = {
  SELECTED:
    "offered to this scan; whether it applied to the target, ran or failed is in the server log, not on the row",
  "NOT RUN": "not selected for this scan",
  UNKNOWN: "this row predates scanners_ran, so whether it ran cannot be established",
};

function ScannerTile({ card }: { card: ScannerCard }) {
  const idle = card.status !== "SELECTED";
  return (
    <article
      data-testid="scanner-card"
      data-status={card.status}
      className={cn(
        "px-3 py-2.5",
        card.status === "SELECTED" && "border border-line bg-panel",
        card.status === "NOT RUN" && "border border-dashed border-line",
        card.status === "UNKNOWN" && "border border-dotted border-ink-faint/60",
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-medium text-ink">{card.label}</span>
        <Tag variant={card.status === "SELECTED" ? "verified" : "provisional"}>
          {card.status === "SELECTED" ? "Selected" : card.status === "NOT RUN" ? "Not run" : "Unknown"}
        </Tag>
      </div>
      <div className="mt-0.5 font-mono text-[10px] text-ink-faint">
        {card.id}
        {card.version ? ` ${card.version}` : ""} · feeds {SCANNER_VIEW[card.id] ?? "—"}
      </div>
      <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-2xs">
        <dt className="text-ink-faint">Artefacts</dt>
        <dd className="text-right font-mono tabular-nums text-ink">{idle ? "—" : card.artefacts}</dd>
        <dt className="text-ink-faint">Provenance</dt>
        <dd className="text-right">
          {idle || card.artefacts === 0 ? (
            <span className="text-ink-faint">—</span>
          ) : card.provisional > 0 ? (
            <Tag variant="provisional">{card.provisional} provisional</Tag>
          ) : (
            <Tag variant="verified">Verified</Tag>
          )}
        </dd>
        <dt className="text-ink-faint">Engine</dt>
        <dd className="text-right font-mono text-[10px] text-ink-dim">
          {card.engine === "UNAVAILABLE" ? <Tag variant="provisional">Unavailable</Tag> : (card.engine ?? "built in")}
        </dd>
      </dl>
      <p className="mt-2 text-[10px] leading-snug text-ink-faint">{FOOTNOTE[card.status]}</p>
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
        title="Coverage"
        subtitle="What this scan looked at — and what it did not. A view nobody collected is not a view that came back clean, and a scanner that did not run found nothing because it did not look."
        actions={
          scan ? (
            <LinkButton href={reportUrl(scan.id, "coverage")} target="_blank" rel="noopener">
              <ExternalLink className="h-3 w-3" aria-hidden /> Coverage statement (PDF)
            </LinkButton>
          ) : undefined
        }
      />
      {!scan ? (
        <div className="p-4">
          <EmptyPanel title="No scan selected" />
        </div>
      ) : (
        <div className="space-y-3 p-4">
          <Panel
            title="Scanners"
            meta={
              scanners.error
                ? "the server's scanner list could not be loaded — showing what this row recorded"
                : scan.scanners_ran === null
                  ? "scanners_ran not recorded for this scan"
                  : `${scan.scanners_ran.length} selected · attributed artefacts prove a scanner looked`
            }
          >
            <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
              {cards.map((card) => (
                <ScannerTile key={card.id} card={card} />
              ))}
              <article data-testid="policy-card" className="border border-line bg-panel px-3 py-2.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-medium text-ink">Policy engine</span>
                  <Tag variant="verified">Scored</Tag>
                </div>
                <div className="mt-0.5 font-mono text-[10px] text-ink-faint">signed knowledge packs</div>
                <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-2xs">
                  <dt className="text-ink-faint">Artefacts scored</dt>
                  <dd className="text-right font-mono tabular-nums text-ink">{artefacts.length}</dd>
                  <dt className="text-ink-faint">Provisional facts</dt>
                  <dd className="text-right font-mono tabular-nums text-ink">{provisional}</dd>
                  <dt className="text-ink-faint">Packs applied</dt>
                  <dd className="text-right text-[10px] text-ink-faint">not exposed by the API</dd>
                </dl>
                <p className="mt-2 text-[10px] leading-snug text-ink-faint">
                  an unverified rule is listed but scores 0 (ADR-0017)
                </p>
              </article>
            </div>
          </Panel>

          <Panel title="Visibility matrix · declared / shipped / observed" bodyClassName="p-0">
            <table className="w-full border-collapse text-xs">
              <thead>
                <tr className="bg-raised text-left text-2xs uppercase tracking-widest text-ink-faint">
                  <th className="border-b border-line px-3 py-1.5 font-medium">View</th>
                  <th className="border-b border-line px-3 py-1.5 font-medium">Collected</th>
                  <th className="border-b border-line px-3 py-1.5 text-right font-medium">Artefacts in view</th>
                  <th className="border-b border-line px-3 py-1.5 text-right font-medium">Seen, incl. correlated</th>
                  <th className="border-b border-line px-3 py-1.5 font-medium">What it tells you</th>
                  <th className="border-b border-line px-3 py-1.5 font-medium">To collect it</th>
                </tr>
              </thead>
              <tbody>
                {VIEWS.map((name) => {
                  const collected = coverage.collected.includes(name);
                  const pulse = coverage.pulse[name];
                  return (
                    <tr key={name} data-testid={`matrix-${name}`} className="border-b border-line-soft align-top">
                      <td className="px-3 py-1.5 font-medium uppercase tracking-wider text-ink-dim">{name}</td>
                      <td className="px-3 py-1.5">
                        <Tag variant={collected ? "verified" : "provisional"}>
                          {collected ? "Collected" : "Not collected"}
                        </Tag>
                      </td>
                      <td className="px-3 py-1.5 text-right font-mono tabular-nums text-ink">
                        {artefacts.filter((a) => a.views.includes(name)).length}
                      </td>
                      <td className="px-3 py-1.5 text-right font-mono tabular-nums text-ink-dim">
                        {collected ? `${pulse.seen}/${pulse.total} · ${pulse.percent}%` : "—"}
                      </td>
                      <td className="px-3 py-1.5 text-2xs text-ink-faint">{VIEW_MEANING[name]}</td>
                      <td className="px-3 py-1.5 text-2xs text-ink-faint">{collected ? "—" : VIEW_REMEDY[name]}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <p className="border-t border-line px-3 py-2 text-2xs text-ink-faint">
              <span className="font-mono tabular-nums text-ink-dim">{scan.coverage_gaps}</span> component(s)
              were correlated against a group missing at least one view (from the scan row), so any
              drift verdict on them rests on fewer sightings than a complete group would give.
            </p>
          </Panel>
        </div>
      )}
    </div>
  );
}
