/**
 * RISK ANALYSIS -- an honest placeholder (ADR-0031).
 *
 * Portfolio risk -- trend across scans, business-impact weighting, blast
 * radius -- is not computed by the backend. A chart here would have to be
 * drawn from numbers nobody measured, so the screen says what IS scoped to
 * the current scan and sends the reader to the screens that answer today.
 */
import type { ScanSummary } from "@/api/types";
import { ScreenHeader } from "@/components/Panel";
import { hrefFor } from "@/lib/router";

const STEPS = [
  { href: hrefFor("inventory"), label: "Inventory", text: "review what this scan found, worst first" },
  { href: hrefFor("drift"), label: "Cryptographic Drift", text: "check where declared, shipped and observed disagree" },
  { href: hrefFor("roadmap"), label: "Migration Roadmap", text: "then prioritise: sequence the work against its deadlines" },
];

export function RiskAnalysisScreen({ scan }: { scan: ScanSummary | null }) {
  return (
    <div>
      <ScreenHeader
        title="Risk Analysis"
        subtitle="Portfolio-level risk analysis is not built. This screen says so rather than drawing a chart it has no data for."
      />
      <div className="p-4">
        <div
          data-testid="risk-placeholder"
          className="max-w-3xl border border-dashed border-line bg-panel px-5 py-5"
        >
          <div className="eyebrow">Prototype · not computed</div>
          <p className="mt-2 text-sm font-medium text-ink">
            Risk analysis is scoped to the current scan
          </p>
          <p className="mt-1.5 text-2xs leading-relaxed text-ink-faint">
            ECDAT scores each artefact in the scan you are looking at
            {scan ? ` (${scan.target.system ?? scan.target.ref})` : ""} — its band, its
            Mosca terms and its deadline — and that is what it computes today. Trends
            across scans, business-impact weighting and blast-radius graphs are not
            built, so nothing here pretends to show them.
          </p>
          <ol className="mt-4 space-y-1.5">
            {STEPS.map((step, index) => (
              <li key={step.href} className="flex items-baseline gap-3 text-xs">
                <span className="w-4 font-mono text-2xs text-ink-faint">{index + 1}</span>
                <a href={step.href} className="font-medium text-ink underline-offset-2 hover:underline">
                  {step.label}
                </a>
                <span className="text-2xs text-ink-faint">{step.text}</span>
              </li>
            ))}
          </ol>
        </div>
        <p className="mt-3 max-w-3xl text-[10px] leading-relaxed text-ink-faint">
          Owed in PUNCHLIST: cross-scan risk trend, business-impact weighting, and a
          blast-radius view built on the correlator's peer data.
        </p>
      </div>
    </div>
  );
}
