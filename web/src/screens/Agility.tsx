/**
 * CRYPTO AGILITY -- rebuilt on the v2 mockup (agility.html; ADR-0039): the
 * agility score and its breakdown beside a gauge, then "where to improve next".
 *
 * REAL today: the configurable share, the configurable / hard-coded split and
 * the not-assessed count, all off `ecdat:configurable` (ADR-0026). NOT
 * COMPUTED: key-store flexibility and protocol negotiation -- the mockup shows
 * sample percentages for both, and nothing in the backend measures either, so
 * those rows say so and draw no bar. Also not reproduced, for the same reason:
 * the mockup's "Target 80%" (no pack defines a target), its "Moderately
 * adaptable" rating (no rubric exists), its "Agility trend / last 6 scans"
 * (nothing stores agility per scan -- the gauge is THIS scan's share, and says
 * so) and its per-component agility percentages (the improve list shows each
 * component's risk score instead, labelled as such).
 */
import { FileText } from "lucide-react";
import { useMemo, useState } from "react";

import type { Artefact } from "@/api/types";
import { NotComputed } from "@/components/Honest";
import { ScreenHeader } from "@/components/Panel";
import { BandTag, EmptyState, PanelHead, useGrown } from "@/components/v2";
import { cn, shortLocator } from "@/lib/format";
import { hrefFor } from "@/lib/router";
import { agility, type Measured } from "@/state/metrics";

const ARC = "M15,80 A60,60 0 0,1 135,80";
const ARC_LENGTH = 188.5;

function Gauge({ measured }: { measured: Measured<number> }) {
  const grown = useGrown();
  const done = measured.status === "computed";
  return (
    <section data-testid="agility-gauge" data-state={measured.status} className="panel gauge-panel in" style={{ animationDelay: "0.08s" }}>
      <div className="w-full">
        <PanelHead title="Configurable share" sub="This scan · no agility history is stored" />
      </div>
      {done ? (
        <>
          <div className="gauge-svg-wrap">
            <svg width="150" height="90" viewBox="0 0 150 90" aria-hidden>
              <path d={ARC} fill="none" stroke="#171c21" strokeWidth="11" strokeLinecap="round" />
              <path
                className="arc"
                d={ARC}
                fill="none"
                stroke="#f5f6f8"
                strokeWidth="11"
                strokeLinecap="round"
                strokeDasharray={ARC_LENGTH}
                strokeDashoffset={ARC_LENGTH * (1 - (grown ? measured.value : 0) / 100)}
              />
            </svg>
            <div className="gauge-center">
              <div className="gauge-num">{measured.value}%</div>
              <div className="gauge-lbl">configurable</div>
            </div>
          </div>
          <div className="gauge-scale w-[150px]">
            <span>0</span>
            <span>100</span>
          </div>
          <div className="gauge-note">{measured.basis}</div>
        </>
      ) : (
        <div className="empty-inline w-full">
          <NotComputed reason={measured.reason} />
        </div>
      )}
    </section>
  );
}

function BarRow({
  testId,
  label,
  value,
  share,
  sub,
  dim = false,
}: {
  testId: string;
  label: string;
  value: string;
  /** Bar width in percent, or null for no bar. */
  share: number | null;
  sub: string;
  dim?: boolean;
}) {
  const grown = useGrown();
  return (
    <div data-testid={testId} data-state="computed" className="bar-metric-item">
      <div className="bar-metric-row">
        <span>{label}</span>
        <span className="mono">{value}</span>
      </div>
      {share !== null ? (
        <div className="bar-metric-track">
          <div className={cn("bar-metric-fill", dim && "dim")} style={{ width: grown ? `${share}%` : 0 }} />
        </div>
      ) : null}
      <div className="bar-metric-note">{sub}</div>
    </div>
  );
}

function NotComputedRow({ testId, label, reason }: { testId: string; label: string; reason: string }) {
  return (
    <div data-testid={testId} data-state="not-computed" className="bar-metric-item">
      <div className="bar-metric-row">
        <span className="text-ink-dim">{label}</span>
        <span className="not-computed-label">Not computed</span>
      </div>
      <div className="bar-metric-track absent" />
      <div className="bar-metric-note">{reason}</div>
    </div>
  );
}

export function AgilityScreen({ artefacts, loading }: { artefacts: Artefact[]; loading: boolean }) {
  const result = useMemo(() => agility(artefacts), [artefacts]);
  const [method, setMethod] = useState(false);
  const assessed = result.configurable + result.hardCoded;
  const pct = (n: number) => Math.round((n / assessed) * 100);

  return (
    <div className="content">
      <ScreenHeader
        title="Crypto Agility"
        subtitle="How easily this estate can swap cryptographic primitives without a rebuild: how much of it changes algorithm by configuration rather than a code change, review and redeploy."
        actions={
          <button type="button" className="btn-ghost" aria-pressed={method} onClick={() => setMethod((open) => !open)}>
            <FileText className="h-3.5 w-3.5" aria-hidden /> Methodology
          </button>
        }
      />
      {loading && artefacts.length === 0 ? (
        <div className="grid-row grid-2b">
          <div className="panel h-72 animate-pulse" />
          <div className="panel h-72 animate-pulse" />
        </div>
      ) : (
        <>
          {method ? (
            <section className="panel mb-3">
              <PanelHead title="What this screen computes" />
              <ul className="mt-2 list-disc space-y-1 pl-5 text-[12px] leading-relaxed text-ink-dim">
                <li>
                  <strong className="text-ink">Configurable share</strong> = configurable ÷ (configurable + hard-coded),
                  from each component's <code className="mono">ecdat:configurable</code> (ADR-0026). Components no
                  scanner could judge are left out of the denominator.
                </li>
                <li>
                  <strong className="text-ink">Key-store flexibility</strong> and{" "}
                  <strong className="text-ink">protocol negotiation</strong> are not computed: nothing in the backend
                  detects key custody or runtime renegotiation yet (PUNCHLIST).
                </li>
                <li>No target, rating or trend is shown: no policy pack defines a target, and no scan stores agility.</li>
              </ul>
            </section>
          ) : null}

          <div className="grid-row grid-2b">
            <section className="panel in" style={{ animationDelay: "0.04s" }}>
              <PanelHead
                title="Crypto agility"
                sub="How much of the estate can swap an algorithm without a code change"
              />
              <div className="metric-hero mt-2">
                {result.share.status === "computed" ? (
                  <span className="metric-hero-num lg">{result.share.value}%</span>
                ) : (
                  <NotComputed reason={result.share.reason} />
                )}
                <div>
                  <div className="metric-hero-tag">Configurable share</div>
                  <div className="metric-hero-note">No target: no policy pack defines one</div>
                </div>
              </div>

              <div className="bar-metric mt-5">
                <BarRow
                  testId="agility-configurable"
                  label="Configurable crypto"
                  value={assessed === 0 ? "—" : `${pct(result.configurable)}%`}
                  share={assessed === 0 ? null : pct(result.configurable)}
                  sub={
                    assessed === 0
                      ? "no component carries a configurability finding"
                      : `${result.configurable} of ${assessed} assessed · algorithm chosen by configuration`
                  }
                />
                <BarRow
                  testId="agility-hard-coded"
                  label="Hard-coded crypto"
                  value={assessed === 0 ? "—" : `${pct(result.hardCoded)}%`}
                  share={assessed === 0 ? null : pct(result.hardCoded)}
                  dim
                  sub={
                    assessed === 0
                      ? "no component carries a configurability finding"
                      : `${result.hardCoded} of ${assessed} assessed · fixed in code: a change is an edit, a review and a redeploy`
                  }
                />
                <BarRow
                  testId="agility-unassessed"
                  label="Not assessed"
                  value={`${result.unassessed}`}
                  share={null}
                  sub="components no scanner could judge — counted neither way"
                />
                <NotComputedRow
                  testId="agility-key-store"
                  label="Key store flexibility"
                  reason={result.keyStore.status === "not-computed" ? result.keyStore.reason : ""}
                />
                <NotComputedRow
                  testId="agility-protocol"
                  label="Protocol negotiation"
                  reason={result.protocol.status === "not-computed" ? result.protocol.reason : ""}
                />
              </div>
            </section>

            <Gauge measured={result.share} />
          </div>

          <section className="panel in" style={{ animationDelay: "0.1s" }}>
            <PanelHead
              title="Where to improve next"
              sub="Hard-coded components, worst first — where making the algorithm configurable pays most"
            />
            {result.improve.length === 0 ? (
              <EmptyState
                title={
                  result.hardCoded === 0 && result.configurable > 0
                    ? "Nothing is hard-coded"
                    : "No component was assessed as hard-coded"
                }
              />
            ) : (
              <div className="mt-2">
                {result.improve.map((artefact) => (
                  <div key={artefact.bomRef} className="improve-row" data-testid="improve-row">
                    <div className="min-w-0">
                      <a
                        href={hrefFor("inventory", { ref: artefact.bomRef })}
                        className="improve-name hover:underline"
                      >
                        {artefact.name}
                      </a>
                      <div className="improve-note">
                        {artefact.occurrences[0] ? shortLocator(artefact.occurrences[0].locator) : "no location"} ·
                        fixed in code — read the algorithm from configuration
                      </div>
                    </div>
                    <BandTag band={artefact.band} />
                    <div className="improve-pct" title="The component's risk score, not an agility percentage">
                      {artefact.score}
                      <small>risk</small>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}
