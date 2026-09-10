/**
 * CRYPTO AGILITY -- laid out as web/design/ has it (ADR-0032): a large gauge
 * beside the agility breakdown, then "where to improve next".
 *
 * REAL today: the configurable share, the configurable / hard-coded split and
 * the not-assessed count, all off `ecdat:configurable` (ADR-0026). NOT
 * COMPUTED: key-store flexibility and protocol negotiation -- the design shows
 * sample percentages for both, and nothing in the backend measures either, so
 * those rows say so and draw no bar. The design's "target 80%" and
 * per-component agility percentages are not reproduced for the same reason.
 */
import { FileText } from "lucide-react";
import { useMemo, useState } from "react";

import type { Artefact } from "@/api/types";
import { EmptyPanel, NotComputed } from "@/components/Honest";
import { BandBadge, Button, Panel, ScreenHeader, SkeletonBlock } from "@/components/Panel";
import { shortLocator } from "@/lib/format";
import { hrefFor } from "@/lib/router";
import { agility, type Measured } from "@/state/metrics";

function Gauge({ measured }: { measured: Measured<number> }) {
  // A half-ring drawn with pathLength=100, so the dash IS the percentage.
  const arc = "M 20 100 A 80 80 0 0 1 180 100";
  const done = measured.status === "computed";
  return (
    <div data-testid="agility-gauge" data-state={measured.status} className="flex flex-col items-center">
      <div className="relative w-full max-w-[22rem]">
        <svg viewBox="0 0 200 108" className="w-full" aria-hidden>
          <path
            d={arc}
            fill="none"
            strokeWidth="22"
            className={done ? "stroke-tint-line" : "stroke-line"}
            strokeDasharray={done ? undefined : "3 4"}
          />
          {done ? (
            <path
              d={arc}
              fill="none"
              strokeWidth="22"
              pathLength={100}
              strokeDasharray={`${measured.value} 100`}
              className="stroke-ink-dim"
            />
          ) : null}
        </svg>
        {done ? (
          <div className="absolute inset-x-0 top-[42%] text-center">
            <span className="text-[52px] font-semibold leading-none tabular-nums text-ink">{measured.value}</span>
            <span className="text-[20px] text-ink-dim">%</span>
          </div>
        ) : null}
      </div>
      {done ? (
        <div className="mt-3 text-center text-[12px] text-ink-faint">{measured.basis}</div>
      ) : (
        <NotComputed reason={measured.reason} className="mt-3 text-center" />
      )}
    </div>
  );
}

function SignalRow({
  testId,
  label,
  value,
  share,
  sub,
}: {
  testId: string;
  label: string;
  value: string;
  /** Bar width in percent, or null for no bar. */
  share: number | null;
  sub: string;
}) {
  return (
    <div data-testid={testId} data-state="computed" className="py-3.5">
      <div className="flex items-baseline justify-between gap-3">
        <span className="text-[13px] text-ink">{label}</span>
        <span className="font-mono text-[13px] tabular-nums text-ink">{value}</span>
      </div>
      {share !== null ? (
        <div className="mt-2 h-1.5 rounded-full bg-line">
          <div className="h-full rounded-full bg-ink/80" style={{ width: `${share}%` }} />
        </div>
      ) : null}
      <div className="mt-1.5 text-[11.5px] text-ink-faint">{sub}</div>
    </div>
  );
}

function NotComputedRow({ testId, label, reason }: { testId: string; label: string; reason: string }) {
  return (
    <div data-testid={testId} data-state="not-computed" className="py-3.5">
      <div className="flex items-baseline justify-between gap-3">
        <span className="text-[13px] text-ink-dim">{label}</span>
        <span className="font-mono text-[10.5px] uppercase tracking-wider text-ink-faint">Not computed</span>
      </div>
      <div className="mt-1.5 text-[11.5px] text-ink-faint">{reason}</div>
    </div>
  );
}

export function AgilityScreen({ artefacts, loading }: { artefacts: Artefact[]; loading: boolean }) {
  const result = useMemo(() => agility(artefacts), [artefacts]);
  const [method, setMethod] = useState(false);
  const assessed = result.configurable + result.hardCoded;
  const pct = (n: number) => Math.round((n / assessed) * 100);

  return (
    <div>
      <ScreenHeader
        title="Crypto Agility"
        subtitle="Measure how readily this estate can adopt new cryptography: how much of it changes algorithm by configuration rather than a code change, review and redeploy."
        actions={
          <Button aria-pressed={method} onClick={() => setMethod((open) => !open)}>
            <FileText className="h-3.5 w-3.5" aria-hidden /> Methodology
          </Button>
        }
      />
      {loading && artefacts.length === 0 ? (
        <div className="px-6 pb-6">
          <SkeletonBlock className="h-72 w-full" />
        </div>
      ) : (
        <div className="space-y-4 px-6 pb-6">
          {method ? (
            <Panel eyebrow="Methodology" title="What this screen computes">
              <ul className="list-disc space-y-1 pl-5 text-[12.5px] leading-relaxed text-ink-dim">
                <li>
                  <strong className="text-ink">Configurable share</strong> = configurable ÷ (configurable +
                  hard-coded), from each component's <code className="font-mono">ecdat:configurable</code>{" "}
                  (ADR-0026). Components no scanner could judge are left out of the denominator.
                </li>
                <li>
                  <strong className="text-ink">Key-store flexibility</strong> and{" "}
                  <strong className="text-ink">protocol negotiation</strong> are not computed: nothing in the
                  backend detects key custody or runtime renegotiation yet (PUNCHLIST).
                </li>
                <li>No target percentage is shown: no policy pack defines one.</li>
              </ul>
            </Panel>
          ) : null}

          <div className="grid gap-4 xl:grid-cols-[1fr_1.45fr]">
            <Panel eyebrow="Current score" title="Configurable share">
              <Gauge measured={result.share} />
            </Panel>
            <Panel eyebrow="Implementation signals" title="Agility breakdown" bodyClassName="divide-y divide-line pt-1">
              <SignalRow
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
              <SignalRow
                testId="agility-hard-coded"
                label="Hard-coded crypto"
                value={assessed === 0 ? "—" : `${pct(result.hardCoded)}%`}
                share={assessed === 0 ? null : pct(result.hardCoded)}
                sub={
                  assessed === 0
                    ? "no component carries a configurability finding"
                    : `${result.hardCoded} of ${assessed} assessed · fixed in code: a change is an edit, a review and a redeploy`
                }
              />
              <SignalRow
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
            </Panel>
          </div>

          <Panel eyebrow="System components" title="Where to improve next" bodyClassName="pt-1">
            {result.improve.length === 0 ? (
              <EmptyPanel
                title={
                  result.hardCoded === 0 && result.configurable > 0
                    ? "Nothing is hard-coded"
                    : "No component was assessed as hard-coded"
                }
              />
            ) : (
              <ul>
                {result.improve.map((artefact) => (
                  <li
                    key={artefact.bomRef}
                    className="grid grid-cols-[minmax(9rem,1fr)_minmax(0,1.3fr)_minmax(0,1.6fr)_auto] items-center gap-4 border-t border-line py-3 first:border-t-0"
                  >
                    <a
                      href={hrefFor("inventory", { ref: artefact.bomRef })}
                      className="truncate text-[13px] font-medium text-ink hover:underline"
                    >
                      {artefact.name}
                    </a>
                    <span className="truncate font-mono text-[11px] text-ink-dim">
                      {artefact.occurrences[0] ? shortLocator(artefact.occurrences[0].locator) : "—"}
                    </span>
                    <span className="truncate text-[12px] text-ink-faint">
                      fixed in code — read the algorithm from configuration
                    </span>
                    <BandBadge band={artefact.band} />
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      )}
    </div>
  );
}
