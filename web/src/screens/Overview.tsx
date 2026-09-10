/**
 * OVERVIEW -- how bad, where, and how it moves with the CRQC horizon.
 *
 * Every band-derived number here is counted from the document ON SCREEN, so
 * the whole screen follows the Mosca slider through a real rescore round trip
 * (ADR-0016). Cards read off the stored ROW (drift) say so, and do not move.
 * Every card is `computed` with its basis or `not-computed` with its reason.
 */
import { ArrowRight } from "lucide-react";
import { useMemo } from "react";

import { BANDS, VIEWS } from "@/api/types";
import { EmptyPanel, MetricCard, NotComputed } from "@/components/Honest";
import { InfoTip } from "@/components/InfoTip";
import { Panel, ScreenHeader, SkeletonBlock } from "@/components/Panel";
import { Slider } from "@/components/ui/slider";
import { BAND_STYLE, cn, shortRef } from "@/lib/format";
import { hrefFor } from "@/lib/router";
import { Z_MAX, Z_MIN, type ScanView } from "@/state/inventory";
import {
  agility,
  computed,
  driftMeasure,
  moscaSummary,
  notComputed,
  priorityQueue,
  quantumExposure,
  scoreHistogram,
  targetOf,
  viewCoverage,
  type Measured,
  type Range,
} from "@/state/metrics";
import { bandCountsOf } from "@/state/presentation";

const MOSCA_EXPLAINER =
  "Mosca's inequality: if the years data must stay secret (x) plus the years " +
  "migration takes (y) exceed the years until a cryptographically relevant " +
  "quantum computer (z), data encrypted today is already exposed. Moving z " +
  "re-scores the stored inventory through the rescore endpoint; nothing is " +
  "re-scanned, and the original verdict stays on record.";

function rangeText(range: Range): string {
  return range.min === range.max ? `${range.min}` : `${range.min}–${range.max}`;
}

function Term({
  label,
  measured,
  note,
}: {
  label: string;
  measured: Measured<Range>;
  note?: string;
}) {
  return (
    <div className="bg-panel px-3 py-2">
      <div className="eyebrow">{label}</div>
      {measured.status === "computed" ? (
        <>
          <div className="mt-0.5 font-mono text-base tabular-nums text-ink">
            {rangeText(measured.value)}
            <span className="ml-0.5 text-2xs text-ink-faint">y</span>
          </div>
          <div className="text-[10px] text-ink-faint">{note ?? measured.basis}</div>
        </>
      ) : (
        <NotComputed reason={measured.reason} className="mt-1" />
      )}
    </div>
  );
}

export function OverviewScreen({ view }: { view: ScanView }) {
  const { scan, artefacts, loading } = view;

  const live = useMemo(() => bandCountsOf(artefacts), [artefacts]);
  const mosca = useMemo(() => moscaSummary(artefacts), [artefacts]);
  const quantum = useMemo(() => quantumExposure(artefacts), [artefacts]);
  const coverage = useMemo(() => viewCoverage(artefacts), [artefacts]);
  const agile = useMemo(() => agility(artefacts), [artefacts]);
  const queue = useMemo(() => priorityQueue(artefacts, 8), [artefacts]);
  const histogram = useMemo(() => scoreHistogram(artefacts), [artefacts]);
  const drift = driftMeasure(scan, artefacts);

  const header = (
    <ScreenHeader
      title="Overview"
      subtitle="What this estate holds, how exposed it is, and how that changes with the CRQC horizon. Band counts follow the slider; nothing on this screen is re-scanned."
    />
  );

  if (loading && artefacts.length === 0) {
    return (
      <div>
        {header}
        <div className="space-y-3 p-4">
          <div className="grid grid-cols-3 gap-px border border-line bg-line sm:grid-cols-5 xl:grid-cols-9">
            {Array.from({ length: 9 }).map((_, i) => (
              <div key={i} className="bg-panel px-3 py-3">
                <SkeletonBlock className="h-2 w-16" />
                <SkeletonBlock className="mt-2 h-5 w-10" />
              </div>
            ))}
          </div>
          <SkeletonBlock className="h-40 w-full" />
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div>
        {header}
        <div className="p-4">
          <EmptyPanel title="No scan in this database">
            Nothing to summarise yet. Run a scan from{" "}
            <a className="text-ink-dim underline" href={hrefFor("scans")}>
              Scans
            </a>
            , or with <code className="font-mono">ecdat scan</code> against the
            same <code className="font-mono">ECDAT_DB</code> the server opened.
          </EmptyPanel>
        </div>
      </div>
    );
  }

  const inBand = (count: number): Measured<number> =>
    computed(count, `at z = ${mosca.z ?? view.zYears}y, on screen`);
  const quantumMeasure: Measured<number> =
    artefacts.length === 0
      ? notComputed("this scan holds no artefacts")
      : computed(
          quantum.broken,
          `${quantum.weakened} weakened · ${quantum.unassessed} without a quantum verdict`,
        );
  const bandTotal = BANDS.reduce((sum, band) => sum + live[band], 0);
  const peak = Math.max(1, ...histogram.map((bucket) => bucket.count));

  return (
    <div>
      {header}
      <div className={cn("space-y-3 p-4 transition-opacity", view.rescoring && "opacity-70")}>
        <div className="grid grid-cols-3 gap-px border border-line bg-line sm:grid-cols-5 xl:grid-cols-9">
          <MetricCard
            id="total"
            label="Artefacts"
            measured={computed(artefacts.length, `${scan.target.kind} · ${scan.target.ref}`)}
          />
          {BANDS.map((band) => (
            <MetricCard
              key={band}
              id={band.toLowerCase()}
              label={band}
              measured={inBand(live[band])}
              tone={live[band] > 0 && band !== "Low" ? BAND_STYLE[band].text : undefined}
            />
          ))}
          <MetricCard
            id="quantum"
            label="Quantum-vulnerable"
            measured={quantumMeasure}
            tone={quantum.broken > 0 ? "text-critical" : undefined}
          />
          <MetricCard id="drift" label="Drift" measured={drift} />
          <MetricCard id="coverage" label="View coverage" measured={coverage.share} unit="%" />
          <MetricCard id="agility" label="Crypto agility" measured={agile.share} unit="%" />
        </div>

        <div className="grid gap-3 lg:grid-cols-[1.3fr_1fr]">
          {/* The Mosca control. Changing Z re-scores the STORED document through
              POST /scans/{id}/rescore -- a new linked row, never an edit. */}
          <Panel title="CRQC horizon · Mosca" meta={<InfoTip label={MOSCA_EXPLAINER} />}>
            <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
              <div className="flex items-baseline gap-1.5">
                <span
                  className={cn(
                    "font-mono text-3xl leading-none tabular-nums transition-colors",
                    view.rescoring ? "text-ink-dim" : "text-ink",
                  )}
                >
                  {view.zYears}
                </span>
                <span className="text-2xs text-ink-faint">years to a CRQC</span>
              </div>
              <div className="flex min-w-[12rem] flex-1 items-center gap-3">
                <span className="font-mono text-2xs tabular-nums text-ink-faint">{Z_MIN}</span>
                <Slider
                  value={[view.zYears]}
                  min={Z_MIN}
                  max={Z_MAX}
                  step={1}
                  aria-label="Years until a cryptographically relevant quantum computer"
                  onValueChange={([value]) => view.setZYears(value)}
                />
                <span className="font-mono text-2xs tabular-nums text-ink-faint">{Z_MAX}</span>
              </div>
            </div>

            <div
              data-testid="live-readout"
              className={cn(
                "mt-3 flex flex-wrap items-center gap-x-5 gap-y-1 transition-opacity",
                view.rescoring ? "opacity-40" : "opacity-100",
              )}
            >
              {BANDS.map((band) => (
                <span key={band} className="flex items-baseline gap-1.5">
                  <span className={cn("h-2 w-2 self-center", BAND_STYLE[band].dot)} />
                  <span
                    data-testid={`live-${band}`}
                    className={cn(
                      "font-mono text-base tabular-nums",
                      live[band] > 0 ? BAND_STYLE[band].text : "text-ink-faint",
                    )}
                  >
                    {live[band]}
                  </span>
                  <span className="text-2xs text-ink-faint">{band}</span>
                </span>
              ))}
              <span className="ml-auto text-[10px] text-ink-faint">
                {view.rescoring ? "re-scoring stored CBOM…" : "live — recomputed on drag"}
              </span>
            </div>

            <div className="mt-3 grid grid-cols-3 gap-px border border-line bg-line">
              <Term label="Data shelf-life · x" measured={mosca.x} note="per data class" />
              <Term label="Migration time · y" measured={mosca.y} note="an estimate, not a measurement" />
              <div data-testid="horizon-delta" className="bg-panel px-3 py-2">
                <div className="eyebrow">Horizon delta · z − (x + y)</div>
                {mosca.delta.status === "computed" ? (
                  <>
                    <div
                      className={cn(
                        "mt-0.5 font-mono text-base tabular-nums",
                        mosca.delta.value.worst < 0 ? "text-critical" : "text-ink",
                      )}
                    >
                      {mosca.delta.value.worst > 0 ? `+${mosca.delta.value.worst}` : mosca.delta.value.worst}
                      <span className="ml-0.5 text-2xs text-ink-faint">y worst</span>
                    </div>
                    <div className="text-[10px] text-ink-faint">
                      {mosca.delta.value.exposed} of {mosca.delta.value.assessed} exposed (x + y &gt; z)
                    </div>
                  </>
                ) : (
                  <NotComputed reason={mosca.delta.reason} className="mt-1" />
                )}
              </div>
            </div>
          </Panel>

          <Panel title="Risk distribution" meta={<span className="font-mono">{bandTotal}</span>}>
            <div className="flex h-2 w-full overflow-hidden bg-line">
              {BANDS.map((band) =>
                live[band] === 0 ? null : (
                  <div
                    key={band}
                    title={`${band}: ${live[band]}`}
                    style={{ width: `${(live[band] / Math.max(1, bandTotal)) * 100}%` }}
                    className={BAND_STYLE[band].dot}
                  />
                ),
              )}
            </div>
            <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
              {BANDS.map((band) => (
                <span key={band} className="flex items-center gap-1.5 text-2xs">
                  <span className={cn("h-2 w-2", BAND_STYLE[band].dot)} />
                  <span className="text-ink-faint">{band}</span>
                  <span className="font-mono tabular-nums text-ink-dim">{live[band]}</span>
                </span>
              ))}
            </div>

            <div className="mt-4 flex items-baseline justify-between">
              <span className="eyebrow">Risk-score histogram</span>
              <span className="font-mono text-[10px] tabular-nums text-ink-faint">peak {peak}</span>
            </div>
            {/* Bars with a baseline and positioned axis labels, so a height means a count. */}
            <div className="mt-1.5 flex h-20 items-end gap-px border-b border-line">
              {histogram.map((bucket) => (
                <div
                  key={bucket.floor}
                  title={`score ${bucket.floor}–${bucket.floor + 9}: ${bucket.count}`}
                  className="flex h-full flex-1 items-end"
                >
                  <div
                    className={cn("w-full", bucket.count === 0 ? "h-px bg-line" : BAND_STYLE[bucket.band].dot)}
                    style={bucket.count === 0 ? undefined : { height: `${(bucket.count / peak) * 100}%` }}
                  />
                </div>
              ))}
            </div>
            <div className="relative mt-1 h-3 font-mono text-[10px] tabular-nums text-ink-faint">
              {[0, 40, 60, 80, 100].map((tick) => (
                <span
                  key={tick}
                  className="absolute -translate-x-1/2 first:translate-x-0 last:-translate-x-full"
                  style={{ left: `${tick}%` }}
                >
                  {tick}
                </span>
              ))}
            </div>
          </Panel>
        </div>

        <div className="grid gap-3 lg:grid-cols-[1.3fr_1fr]">
          <Panel
            title="Priority findings"
            meta={
              <a href={hrefFor("inventory")} className="inline-flex items-center gap-1 hover:text-ink">
                Inventory <ArrowRight className="h-3 w-3" aria-hidden />
              </a>
            }
            bodyClassName="p-0"
          >
            {queue.length === 0 ? (
              <EmptyPanel className="m-3" title="This scan found no cryptographic artefacts" />
            ) : (
              <ol>
                {queue.map((artefact) => {
                  const target = targetOf(artefact);
                  return (
                    <li key={artefact.bomRef} className="border-b border-line-soft last:border-b-0">
                      <a
                        href={hrefFor("inventory", { ref: artefact.bomRef })}
                        className={cn(
                          "grid grid-cols-[1fr_auto_auto] items-baseline gap-3 border-l-2 px-3 py-1.5 transition-colors hover:bg-raised/60",
                          artefact.band === "Critical"
                            ? "border-l-critical"
                            : artefact.band === "High"
                              ? "border-l-high"
                              : "border-l-transparent",
                        )}
                      >
                        <span className="min-w-0 truncate">
                          <span className="text-xs font-medium text-ink">{artefact.name}</span>
                          <span className="ml-2 font-mono text-[10px] text-ink-faint">
                            {shortRef(artefact.bomRef)}
                          </span>
                          <span className="ml-2 text-2xs text-ink-faint">
                            {artefact.usage}
                            {target ? ` → ${target}` : ""}
                          </span>
                        </span>
                        <span
                          className={cn(
                            "font-mono text-[10px] tabular-nums",
                            artefact.deadlineProvisional ? "text-ink-faint line-through" : "text-ink-dim",
                          )}
                        >
                          {artefact.deadline ?? "no deadline"}
                        </span>
                        <span
                          className={cn(
                            "w-8 text-right font-mono text-xs tabular-nums",
                            BAND_STYLE[artefact.band].text,
                          )}
                        >
                          {artefact.score}
                        </span>
                      </a>
                    </li>
                  );
                })}
              </ol>
            )}
          </Panel>

          <Panel
            title="Coverage pulse"
            meta={
              <a href={hrefFor("coverage")} className="inline-flex items-center gap-1 hover:text-ink">
                Coverage <ArrowRight className="h-3 w-3" aria-hidden />
              </a>
            }
          >
            <div className="space-y-2.5">
              {VIEWS.map((name) => {
                const pulse = coverage.pulse[name];
                const collected = coverage.collected.includes(name);
                return (
                  <div key={name} data-testid={`pulse-${name}`}>
                    <div className="flex items-baseline justify-between text-2xs">
                      <span className="uppercase tracking-wider text-ink-dim">{name}</span>
                      {collected ? (
                        <span className="font-mono tabular-nums text-ink-dim">
                          {pulse.percent}%{" "}
                          <span className="text-ink-faint">
                            {pulse.seen}/{pulse.total}
                          </span>
                        </span>
                      ) : (
                        <span className="text-ink-faint">not collected</span>
                      )}
                    </div>
                    <div
                      className={cn(
                        "mt-1 h-1.5 w-full",
                        collected ? "bg-line" : "border border-dashed border-line",
                      )}
                    >
                      {collected ? (
                        <div className="h-full bg-ink-dim" style={{ width: `${pulse.percent}%` }} />
                      ) : null}
                    </div>
                  </div>
                );
              })}
            </div>
            <p className="mt-3 text-[10px] leading-relaxed text-ink-faint">
              Share of artefacts sighted in each view, directly or through their
              correlation group. A view nobody collected is a gap, not a clean result.
            </p>
          </Panel>
        </div>
      </div>
    </div>
  );
}
