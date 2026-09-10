/**
 * RISK ANALYSIS -- an honest placeholder (ADR-0031), in the design's centred
 * empty-state card (ADR-0032).
 *
 * Portfolio risk -- trend across scans, business-impact weighting, blast
 * radius -- is not computed by the backend. A chart here would have to be
 * drawn from numbers nobody measured, so the card says what IS scoped to the
 * current scan and sends the reader to the screens that answer today.
 */
import { ArrowRight, Lock } from "lucide-react";

import type { ScanSummary } from "@/api/types";
import { LinkButton, Panel, Pill, ScreenHeader } from "@/components/Panel";
import { hrefFor } from "@/lib/router";

export function RiskAnalysisScreen({ scan }: { scan: ScanSummary | null }) {
  return (
    <div>
      <ScreenHeader
        title="Risk Analysis"
        subtitle="Prioritise quantum exposure by business and network context. Not computed yet — this screen says so rather than drawing a chart it has no data for."
      />
      <div className="px-6 pb-6">
        <Panel eyebrow="Analyst workspace" title="Risk analysis queue" meta={<Pill>Prototype · not computed</Pill>}>
          <div data-testid="risk-placeholder" className="flex flex-col items-center px-6 py-14 text-center">
            <span className="flex h-12 w-12 items-center justify-center rounded-full border border-line text-ink-dim">
              <Lock className="h-5 w-5" aria-hidden />
            </span>
            <p className="mt-4 text-[14px] font-semibold text-ink">Risk analysis is scoped to the current scan</p>
            <p className="mt-2 max-w-xl text-[12.5px] leading-relaxed text-ink-faint">
              ECDAT scores each artefact in the scan you are looking at
              {scan ? ` (${scan.target.system ?? scan.target.ref})` : ""} — its band, its Mosca
              terms and its deadline — and that is all it computes today. Trend across scans,
              business-impact weighting and blast radius are not built, so nothing here pretends
              to show them. Use Inventory and{" "}
              <a href={hrefFor("drift")} className="text-ink-dim underline underline-offset-2 hover:text-ink">
                Cryptographic Drift
              </a>{" "}
              to inspect the evidence chain, then sequence the work in the Migration Roadmap.
            </p>
            <LinkButton href={hrefFor("inventory")} className="mt-6">
              Open inventory <ArrowRight className="h-3.5 w-3.5" aria-hidden />
            </LinkButton>
          </div>
        </Panel>
        <p className="mt-3 text-[11px] leading-relaxed text-ink-faint">
          Owed in PUNCHLIST: cross-scan risk trend, business-impact weighting, and a blast-radius
          view built on the correlator's peer data.
        </p>
      </div>
    </div>
  );
}
