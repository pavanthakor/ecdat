/**
 * CRYPTO AGILITY -- how much of the estate can change algorithm without a
 * code change.
 *
 * REAL today: configurable, hard-coded and not-assessed counts, off
 * `ecdat:configurable` (ADR-0026), and the configurable share of the assessed
 * components. NOT COMPUTED: key-store custody and protocol renegotiation --
 * nothing in the backend measures either, so those rows say so and draw no
 * bar. The share excludes the not-assessed from its denominator: "no scanner
 * could tell" is not "hard-coded".
 */
import { useMemo } from "react";

import type { Artefact } from "@/api/types";
import { EmptyPanel, NotComputed } from "@/components/Honest";
import { Panel, ScreenHeader, SkeletonBlock } from "@/components/Panel";
import { BAND_STYLE, cn, shortLocator, shortRef } from "@/lib/format";
import { hrefFor } from "@/lib/router";
import { agility, type Measured } from "@/state/metrics";

function Gauge({ measured }: { measured: Measured<number> }) {
  // A half-ring, drawn with pathLength=100 so the dash IS the percentage.
  const arc = "M 10 60 A 50 50 0 0 1 110 60";
  return (
    <div data-testid="agility-gauge" data-state={measured.status} className="flex flex-col items-center">
      <svg viewBox="0 0 120 66" className="w-full max-w-[15rem]" aria-hidden>
        <path
          d={arc}
          fill="none"
          strokeWidth="9"
          className={measured.status === "computed" ? "stroke-line" : "stroke-line/60"}
          strokeDasharray={measured.status === "computed" ? undefined : "2 3"}
        />
        {measured.status === "computed" ? (
          <path
            d={arc}
            fill="none"
            strokeWidth="9"
            pathLength={100}
            strokeDasharray={`${measured.value} 100`}
            className="stroke-ink-dim"
          />
        ) : null}
      </svg>
      {measured.status === "computed" ? (
        <div className="-mt-7 text-center">
          <div className="font-mono text-3xl leading-none tabular-nums text-ink">{measured.value}%</div>
          <div className="mt-2 text-2xs text-ink-faint">{measured.basis}</div>
        </div>
      ) : (
        <NotComputed reason={measured.reason} className="-mt-4 text-center" />
      )}
    </div>
  );
}

function CountRow({
  testId,
  label,
  note,
  count,
  total,
}: {
  testId: string;
  label: string;
  note: string;
  count: number;
  total: number;
}) {
  return (
    <div data-testid={testId} data-state="computed" className="grid grid-cols-[9rem_1fr_3rem] items-center gap-3 py-2">
      <div>
        <div className="text-xs text-ink">{label}</div>
        <div className="text-[10px] leading-snug text-ink-faint">{note}</div>
      </div>
      <div className="h-1.5 bg-line">
        <div className="h-full bg-ink-dim" style={{ width: `${total === 0 ? 0 : (count / total) * 100}%` }} />
      </div>
      <div className="text-right font-mono text-sm tabular-nums text-ink">{count}</div>
    </div>
  );
}

function NotComputedRow({ testId, label, reason }: { testId: string; label: string; reason: string }) {
  return (
    <div data-testid={testId} data-state="not-computed" className="grid grid-cols-[9rem_1fr] items-center gap-3 py-2">
      <div className="text-xs text-ink-dim">{label}</div>
      <div className="border border-dashed border-line px-2 py-1">
        <NotComputed reason={reason} />
      </div>
    </div>
  );
}

export function AgilityScreen({ artefacts, loading }: { artefacts: Artefact[]; loading: boolean }) {
  const result = useMemo(() => agility(artefacts), [artefacts]);

  return (
    <div>
      <ScreenHeader
        title="Crypto Agility"
        subtitle="How much of this estate can change algorithm by configuration rather than a code change, review and redeploy. Only what the CBOM records is shown; everything else says it is not computed."
      />
      {loading && artefacts.length === 0 ? (
        <div className="p-4">
          <SkeletonBlock className="h-40 w-full" />
        </div>
      ) : (
        <div className="space-y-3 p-4">
          <div className="grid gap-3 lg:grid-cols-[19rem_1fr]">
            <Panel title="Configurable share">
              <Gauge measured={result.share} />
            </Panel>
            <Panel
              title="Agility breakdown"
              meta="real: configurable · hard-coded · not assessed — not computed: key store · protocol"
              bodyClassName="divide-y divide-line-soft px-3 py-1"
            >
              <CountRow
                testId="agility-configurable"
                label="Configurable"
                note="algorithm chosen by configuration"
                count={result.configurable}
                total={artefacts.length}
              />
              <CountRow
                testId="agility-hard-coded"
                label="Hard-coded"
                note="fixed in code: a change is an edit, a review and a redeploy"
                count={result.hardCoded}
                total={artefacts.length}
              />
              <CountRow
                testId="agility-unassessed"
                label="Not assessed"
                note="no scanner could tell; counted neither way"
                count={result.unassessed}
                total={artefacts.length}
              />
              <NotComputedRow testId="agility-key-store" label="Key store" reason={result.keyStore.status === "not-computed" ? result.keyStore.reason : ""} />
              <NotComputedRow
                testId="agility-protocol"
                label="Protocol negotiation"
                reason={result.protocol.status === "not-computed" ? result.protocol.reason : ""}
              />
            </Panel>
          </div>

          <Panel title={`Where to improve · hard-coded (${result.improve.length})`} bodyClassName="p-0">
            {result.improve.length === 0 ? (
              <EmptyPanel
                className="m-3"
                title={result.hardCoded === 0 && result.configurable > 0 ? "Nothing is hard-coded" : "No component was assessed as hard-coded"}
              />
            ) : (
              <table className="w-full border-collapse text-xs">
                <thead>
                  <tr className="bg-raised text-left text-2xs uppercase tracking-widest text-ink-faint">
                    <th className="border-b border-line px-3 py-1.5 font-medium">Artefact</th>
                    <th className="border-b border-line px-3 py-1.5 text-right font-medium">Score</th>
                    <th className="border-b border-line px-3 py-1.5 font-medium">Fixed at</th>
                    <th className="border-b border-line px-3 py-1.5 font-medium">To improve</th>
                  </tr>
                </thead>
                <tbody>
                  {result.improve.map((artefact) => (
                    <tr key={artefact.bomRef} className="border-b border-line-soft">
                      <td className="px-3 py-1">
                        <a href={hrefFor("inventory", { ref: artefact.bomRef })} className="font-medium text-ink hover:underline">
                          {artefact.name}
                        </a>
                        <span className="ml-2 font-mono text-[10px] text-ink-faint">{shortRef(artefact.bomRef)}</span>
                      </td>
                      <td className={cn("px-3 py-1 text-right font-mono tabular-nums", BAND_STYLE[artefact.band].text)}>
                        {artefact.score}
                      </td>
                      <td className="px-3 py-1 font-mono text-[10px] text-ink-dim">
                        {artefact.occurrences[0] ? shortLocator(artefact.occurrences[0].locator) : "—"}
                      </td>
                      <td className="px-3 py-1 text-2xs text-ink-faint">
                        read the algorithm from configuration so a migration is a restart, not a release
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>
        </div>
      )}
    </div>
  );
}
