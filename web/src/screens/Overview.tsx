/**
 * OVERVIEW -- "Cryptographic Security Overview", laid out as web/design/ has it
 * (ADR-0032): nine metric cards on a five-column grid, risk distribution beside
 * the CRQC horizon, then the priority queue beside the coverage pulse.
 *
 * Every band-derived number is counted from the document ON SCREEN, so the
 * whole screen follows the Mosca slider through a real rescore round trip
 * (ADR-0016). Every card is `computed` with its basis or `not-computed` with
 * its reason. The design's sample captions ("+4 pts since baseline") are not
 * reproduced -- nothing computes them.
 */
import { ArrowRight, ChevronRight, Download } from "lucide-react";
import { useMemo } from "react";

import { cbomUrl } from "@/api/client";
import { BANDS, VIEWS } from "@/api/types";
import { EmptyPanel, MetricCard, NotComputed } from "@/components/Honest";
import { InfoTip } from "@/components/InfoTip";
import { BandBadge, LinkButton, Panel, ScreenHeader, SkeletonBlock, Tag } from "@/components/Panel";
import { Slider } from "@/components/ui/slider";
import { BAND_STYLE, cn, pad2, shortLocator } from "@/lib/format";
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

/** Slider tick marks, as horizons in years; labelled as calendar years. */
const TICKS = [5, 10, 15, 20].filter((z) => z >= Z_MIN && z <= Z_MAX);

function yearsText(range: Range): string {
  return range.min === range.max ? `${range.min} years` : `${range.min}–${range.max} years`;
}

function Term({ label, measured }: { label: string; measured: Measured<Range> }) {
  return (
    <div className="min-w-0">
      <div className="eyebrow">{label}</div>
      {measured.status === "computed" ? (
        <div className="mt-1.5 font-mono text-[14px] text-ink">{yearsText(measured.value)}</div>
      ) : (
        <NotComputed reason={measured.reason} className="mt-1.5" />
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
  const queue = useMemo(() => priorityQueue(artefacts, 6), [artefacts]);
  const histogram = useMemo(() => scoreHistogram(artefacts), [artefacts]);
  const drift = driftMeasure(scan, artefacts);
  const baseYear = new Date().getUTCFullYear();

  const header = (
    <ScreenHeader
      title="Cryptographic Security Overview"
      subtitle={
        scan
          ? `${scan.target.system ?? scan.target.ref} / scan ${scan.id.slice(0, 8)} · ${scan.target.kind} ${scan.target.ref}`
          : "No scan loaded"
      }
      actions={
        scan ? (
          <LinkButton
            href={cbomUrl(scan.id)}
            download={`qorbit-cbom-${scan.id.slice(0, 8)}.json`}
            title="Download the stored CBOM this overview is computed from"
          >
            <Download className="h-3.5 w-3.5" aria-hidden /> Export snapshot
          </LinkButton>
        ) : undefined
      }
    />
  );

  if (loading && artefacts.length === 0) {
    return (
      <div>
        {header}
        <div className="space-y-4 px-6 pb-6">
          <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-5">
            {Array.from({ length: 9 }).map((_, i) => (
              <SkeletonBlock key={i} className="h-[6.5rem]" />
            ))}
          </div>
          <SkeletonBlock className="h-72 w-full" />
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div>
        {header}
        <div className="px-6 pb-6">
          <EmptyPanel title="No scan in this database">
            Nothing to summarise yet. Run a scan from{" "}
            <a className="text-ink-dim underline" href={hrefFor("scans")}>
              Scans
            </a>
            , or with <code className="font-mono">ecdat scan</code> against the same{" "}
            <code className="font-mono">ECDAT_DB</code> the server opened.
          </EmptyPanel>
        </div>
      </div>
    );
  }

  const total = artefacts.length;
  const ofInventory = (n: number) =>
    total === 0 ? "of an empty inventory" : `${Math.round((n / total) * 100)}% of inventory`;
  const quantumMeasure: Measured<number> =
    total === 0
      ? notComputed("this scan holds no artefacts")
      : computed(quantum.broken, `${ofInventory(quantum.broken)} · ${quantum.unassessed} without a verdict`);
  const peak = Math.max(1, ...histogram.map((bucket) => bucket.count));
  const exposed = mosca.delta.status === "computed" ? mosca.delta.value.exposed : null;

  return (
    <div>
      {header}
      <div className={cn("space-y-4 px-6 pb-6 transition-opacity", view.rescoring && "opacity-70")}>
        <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-5">
          <MetricCard
            id="total"
            label="Total artefacts"
            measured={computed(total, `across ${coverage.collected.length} of 3 evidence layers`)}
          />
          {BANDS.map((band) => (
            <MetricCard
              key={band}
              id={band.toLowerCase()}
              label={band}
              pad
              measured={computed(live[band], ofInventory(live[band]))}
            />
          ))}
          <MetricCard id="quantum" label="Quantum vulnerable" pad measured={quantumMeasure} />
          <MetricCard id="drift" label="Drift findings" pad measured={drift} />
          <MetricCard id="coverage" label="Coverage" unit="%" measured={coverage.share} />
          <MetricCard id="agility" label="Crypto agility" unit="%" measured={agile.share} />
        </div>

        <div className="grid gap-4 xl:grid-cols-[1.4fr_1fr]">
          <Panel
            eyebrow="Current scan / severity"
            title="Risk distribution"
            meta={<span className="font-mono text-[10.5px] uppercase tracking-wider">{total} artefacts</span>}
          >
            <div className="flex h-3 w-full gap-1">
              {BANDS.map((band) =>
                live[band] === 0 ? null : (
                  <div
                    key={band}
                    title={`${band}: ${live[band]}`}
                    style={{ flexGrow: live[band] }}
                    className={cn("rounded-[3px]", BAND_STYLE[band].dot)}
                  />
                ),
              )}
              {total === 0 ? <div className="flex-1 rounded-[3px] border border-dashed border-line" /> : null}
            </div>
            <div className="mt-3 grid grid-cols-2 gap-y-1 sm:grid-cols-4">
              {BANDS.map((band) => (
                <div key={band} className="flex items-center justify-between gap-2 pr-4">
                  <span className="flex items-center gap-1.5 text-[12px] text-ink-dim">
                    <span className={cn("h-2 w-2 rounded-full", BAND_STYLE[band].dot)} aria-hidden />
                    {band}
                  </span>
                  <span className="font-mono text-[12px] tabular-nums text-ink">{pad2(live[band])}</span>
                </div>
              ))}
            </div>

            <div className="mt-5 border-t border-line pt-4">
              <div className="flex items-baseline justify-between">
                <span className="eyebrow">Risk score distribution</span>
                <span className="font-mono text-[10.5px] uppercase tracking-wider text-ink-faint">
                  Score / 100 · peak {peak}
                </span>
              </div>
              {/* Bars with a baseline and positioned ticks, so a height means a count. */}
              <div className="mt-3 flex h-24 items-end gap-1.5 border-b border-line">
                {histogram.map((bucket) => (
                  <div
                    key={bucket.floor}
                    title={`score ${bucket.floor}–${bucket.floor + 9}: ${bucket.count}`}
                    className="flex h-full flex-1 items-end"
                  >
                    <div
                      className={cn(
                        "w-full rounded-t-[2px]",
                        bucket.count === 0 ? "h-px bg-line" : BAND_STYLE[bucket.band].dot,
                      )}
                      style={bucket.count === 0 ? undefined : { height: `${(bucket.count / peak) * 100}%` }}
                    />
                  </div>
                ))}
              </div>
              <div className="relative mt-1.5 h-3 font-mono text-[10px] tabular-nums text-ink-faint">
                {[0, 25, 50, 75, 100].map((tick) => (
                  <span
                    key={tick}
                    className={cn(
                      "absolute -translate-x-1/2",
                      tick === 0 && "translate-x-0",
                      tick === 100 && "-translate-x-full",
                    )}
                    style={{ left: `${tick}%` }}
                  >
                    {pad2(tick)}
                  </span>
                ))}
              </div>
            </div>
          </Panel>

          {/* The Mosca control. Changing Z re-scores the STORED document through
              POST /scans/{id}/rescore -- a new linked row, never an edit. */}
          <Panel
            eyebrow="Quantum risk model / Mosca"
            title={
              <span className="flex items-center gap-2">
                CRQC horizon <InfoTip label={MOSCA_EXPLAINER} />
              </span>
            }
            meta={
              exposed === null ? null : exposed > 0 ? (
                <span className="rounded-[3px] border border-critical/60 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-critical">
                  At risk
                </span>
              ) : (
                <Tag>Within horizon</Tag>
              )
            }
          >
            <div className="flex flex-wrap items-end justify-between gap-4">
              <div>
                <div
                  className={cn(
                    "font-mono text-[40px] font-light leading-none tabular-nums transition-colors",
                    view.rescoring ? "text-ink-dim" : "text-ink",
                  )}
                >
                  {baseYear + view.zYears}
                </div>
                <div className="mt-1.5 text-[12px] text-ink-faint">
                  Assumed CRQC horizon · z = {view.zYears} years
                </div>
              </div>
              <div className="text-right">
                {exposed === null ? (
                  <div className="text-[12px] text-ink-faint">affected findings not computed</div>
                ) : (
                  <div className="font-mono text-[13px] text-ink" title="artefacts where x + y > z">
                    {exposed} affected findings
                  </div>
                )}
                <div className="mt-0.5 text-[11px] text-ink-faint">
                  {view.rescoring ? "re-scoring the stored CBOM…" : "Live model consequence"}
                </div>
              </div>
            </div>

            <div className="mt-6">
              <Slider
                value={[view.zYears]}
                min={Z_MIN}
                max={Z_MAX}
                step={1}
                aria-label="Years until a cryptographically relevant quantum computer"
                onValueChange={([value]) => view.setZYears(value)}
              />
              <div className="relative mt-2.5 h-3 font-mono text-[10.5px] tabular-nums text-ink-faint">
                {TICKS.map((z) => (
                  <span
                    key={z}
                    className={cn(
                      "absolute -translate-x-1/2",
                      z === Z_MIN && "translate-x-0",
                      z === Z_MAX && "-translate-x-full",
                      z === view.zYears && "font-semibold text-ink",
                    )}
                    style={{ left: `${((z - Z_MIN) / (Z_MAX - Z_MIN)) * 100}%` }}
                  >
                    {baseYear + z}
                  </span>
                ))}
              </div>
            </div>

            <div
              data-testid="live-readout"
              className={cn(
                "mt-6 grid grid-cols-4 divide-x divide-line border-t border-line pt-4 transition-opacity",
                view.rescoring ? "opacity-40" : "opacity-100",
              )}
            >
              {BANDS.map((band) => (
                <div key={band} className="px-3 first:pl-0">
                  <span className={cn("block h-1.5 w-1.5 rounded-full", BAND_STYLE[band].dot)} aria-hidden />
                  <div data-testid={`live-${band}`} className="mt-2 text-xl tabular-nums text-ink">
                    {live[band]}
                  </div>
                  <div className="text-[11px] text-ink-faint">{band}</div>
                </div>
              ))}
            </div>

            <div className="mt-4 grid grid-cols-3 gap-4 border-t border-line pt-4">
              <Term label="Data shelf life" measured={mosca.x} />
              <Term label="Migration time" measured={mosca.y} />
              <div data-testid="horizon-delta" className="min-w-0">
                <div className="eyebrow">Horizon delta</div>
                {mosca.delta.status === "computed" ? (
                  <>
                    <div
                      className={cn(
                        "mt-1.5 font-mono text-[14px]",
                        mosca.delta.value.worst < 0 ? "text-critical" : "text-ink",
                      )}
                    >
                      {mosca.delta.value.worst > 0 ? `+${mosca.delta.value.worst}` : mosca.delta.value.worst} years
                    </div>
                    <div className="mt-0.5 text-[10.5px] text-ink-faint">z − (x + y), worst component</div>
                  </>
                ) : (
                  <NotComputed reason={mosca.delta.reason} className="mt-1.5" />
                )}
              </div>
            </div>
          </Panel>
        </div>

        <div className="grid gap-4 xl:grid-cols-[1.4fr_1fr]">
          <Panel
            eyebrow="Investigation queue"
            title="Priority findings"
            meta={
              <a
                href={hrefFor("inventory")}
                className="inline-flex items-center gap-1 text-[13px] font-medium text-ink hover:text-white"
              >
                View inventory <ArrowRight className="h-3.5 w-3.5" aria-hidden />
              </a>
            }
            bodyClassName="pt-2"
          >
            {queue.length === 0 ? (
              <EmptyPanel title="This scan found no cryptographic artefacts" />
            ) : (
              <ol>
                {queue.map((artefact) => {
                  const target = targetOf(artefact);
                  const place =
                    artefact.endpoint ??
                    (artefact.occurrences[0] ? shortLocator(artefact.occurrences[0].locator) : "no location");
                  return (
                    <li key={artefact.bomRef} className="border-t border-line first:border-t-0">
                      <a
                        href={hrefFor("inventory", { ref: artefact.bomRef })}
                        className="flex items-center gap-4 py-3 transition-colors hover:bg-raised/40"
                      >
                        <span
                          className={cn("h-10 w-[3px] shrink-0 rounded-full", BAND_STYLE[artefact.band].dot)}
                          aria-hidden
                        />
                        <span className="min-w-0 flex-1">
                          <span className="flex flex-wrap items-center gap-2">
                            <span className="text-[14px] font-semibold text-ink">{artefact.name}</span>
                            <BandBadge band={artefact.band} />
                            {artefact.drift.length > 0 ? <Tag variant="strong">Drift</Tag> : null}
                          </span>
                          <span className="mt-1 block truncate font-mono text-[11.5px] text-ink-faint">
                            {place} · {artefact.usage}
                            {target ? ` → ${target}` : ""}
                          </span>
                        </span>
                        <span className="shrink-0 text-right">
                          <span className="block text-xl tabular-nums text-ink">{artefact.score}</span>
                          <span className="eyebrow">Risk score</span>
                        </span>
                        <ChevronRight className="h-4 w-4 shrink-0 text-ink-faint" aria-hidden />
                      </a>
                    </li>
                  );
                })}
              </ol>
            )}
          </Panel>

          <Panel
            eyebrow="Evidence layers"
            title="Coverage pulse"
            meta={
              coverage.share.status === "computed" ? (
                <span className="text-[26px] font-semibold leading-none tabular-nums text-ink">
                  {coverage.share.value}%
                </span>
              ) : (
                <span className="font-mono text-[10.5px] uppercase tracking-wider">not computed</span>
              )
            }
          >
            <div className="space-y-4">
              {VIEWS.map((name) => {
                const pulse = coverage.pulse[name];
                const collected = coverage.collected.includes(name);
                return (
                  <div key={name} data-testid={`pulse-${name}`}>
                    <div className="flex items-baseline justify-between text-[11.5px]">
                      <span className="font-medium uppercase tracking-wider text-ink">{name}</span>
                      <span className="font-mono tabular-nums text-ink-dim">
                        {collected ? `${pulse.percent}%` : "not collected"}
                      </span>
                    </div>
                    <div
                      className={cn(
                        "mt-2 h-2 w-full rounded-full",
                        collected ? "bg-line" : "border border-dashed border-line",
                      )}
                    >
                      {collected ? (
                        <div className="h-full rounded-full bg-ink/80" style={{ width: `${pulse.percent}%` }} />
                      ) : null}
                    </div>
                    <div className="mt-1.5 text-[11px] text-ink-faint">
                      {collected
                        ? `${pulse.seen} of ${pulse.total} artefacts sighted in this view or its correlation group`
                        : "nothing in this scan says anything about this view"}
                    </div>
                  </div>
                );
              })}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
