/**
 * The strip a reader lands on: what is in this estate, and how bad is it.
 *
 * Every number comes off the DENORMALISED scan row (ADR-0016) rather than from
 * counting the CBOM in the browser — the row is what the store recorded, so
 * the strip cannot disagree with the document it summarises.
 *
 * The score distribution is a labelled bar chart with an axis, not a row of
 * floating bars. Bars without a scale are decoration: a reader cannot tell
 * whether a tall one means five artefacts or fifty.
 */
import type { Artefact, Band, ScanSummary } from "@/api/types";
import { BANDS } from "@/api/types";
import { BAND_STYLE, cn } from "@/lib/format";

interface Props {
  scan: ScanSummary | null;
  artefacts: Artefact[];
}

function Metric({
  label,
  value,
  sub,
  tone,
}: {
  label: string;
  value: string | number;
  sub?: string;
  tone?: string;
}) {
  return (
    <div className="px-4 py-2.5">
      <div className="text-2xs uppercase tracking-widest text-ink-faint">{label}</div>
      <div
        className={cn(
          "font-mono text-xl leading-tight tabular-nums text-ink",
          tone,
        )}
      >
        {value}
      </div>
      {sub ? (
        <div className="mt-0.5 truncate text-2xs text-ink-faint" title={sub}>
          {sub}
        </div>
      ) : null}
    </div>
  );
}

/**
 * Coverage, told honestly.
 *
 * `null` means the row predates the column and we cannot say what ran; `[]`
 * means we can, and nothing did (ADR-0016). Rendering both as "none" would
 * turn "never looked for binaries" into "binaries were clean".
 */
function coverageLabel(scanners: ScanSummary["scanners_ran"]): {
  value: string;
  sub: string;
} {
  if (scanners === null) return { value: "—", sub: "not recorded for this scan" };
  if (scanners.length === 0) return { value: "0", sub: "no scanner ran" };
  return {
    value: String(scanners.length),
    sub: scanners.map((s) => s.id).join(" · "),
  };
}

export function SummaryStrip({ scan, artefacts }: Props) {
  if (!scan) return null;

  const counts = scan.band_counts;
  const total = BANDS.reduce((sum, band) => sum + (counts[band] ?? 0), 0) || 1;
  const driftTotal = Object.values(scan.drift_counts ?? {}).reduce(
    (sum, n) => sum + n,
    0,
  );
  const coverage = coverageLabel(scan.scanners_ran);

  // Ten-point buckets, coloured by the band each falls in. Built from the
  // artefacts currently loaded so it tracks a rescore.
  const buckets = Array.from({ length: 10 }, (_, index) => ({
    floor: index * 10,
    count: 0,
  }));
  for (const artefact of artefacts) {
    buckets[Math.min(9, Math.floor(artefact.score / 10))].count += 1;
  }
  const peak = Math.max(1, ...buckets.map((b) => b.count));
  const bucketBand = (floor: number): Band =>
    floor >= 80 ? "Critical" : floor >= 60 ? "High" : floor >= 40 ? "Medium" : "Low";

  return (
    <section className="border-b border-line bg-panel">
      <div className="grid grid-cols-2 divide-x divide-line lg:grid-cols-4">
        <Metric
          label="Artefacts"
          value={scan.component_count}
          sub={`${scan.target.kind} · ${scan.target.ref}`}
        />
        <Metric
          label="Max score"
          value={scan.max_score}
          sub={`${counts.Critical ?? 0} critical · ${counts.High ?? 0} high`}
          tone={scan.max_score >= 80 ? "text-critical" : undefined}
        />
        <Metric
          label="Drift"
          value={driftTotal}
          sub={
            driftTotal === 0
              ? scan.coverage_gaps > 0
                ? `${scan.coverage_gaps} components missing a view`
                : "all views agree"
              : Object.keys(scan.drift_counts).join(" · ")
          }
          tone={driftTotal > 0 ? "text-high" : undefined}
        />
        <Metric label="Scanners" value={coverage.value} sub={coverage.sub} />
      </div>

      <div className="grid grid-cols-1 divide-y divide-line border-t border-line lg:grid-cols-[1fr_24rem] lg:divide-x lg:divide-y-0">
        <div className="px-4 py-3">
          <div className="mb-2 flex items-baseline justify-between">
            <span className="text-2xs uppercase tracking-widest text-ink-faint">
              Band distribution
            </span>
            <span className="font-mono text-2xs tabular-nums text-ink-faint">
              {total}
            </span>
          </div>
          <div className="flex h-2 w-full overflow-hidden">
            {BANDS.map((band) => {
              const count = counts[band] ?? 0;
              if (count === 0) return null;
              return (
                <div
                  key={band}
                  title={`${band}: ${count}`}
                  style={{ width: `${(count / total) * 100}%` }}
                  className={BAND_STYLE[band].dot}
                />
              );
            })}
          </div>
          <div className="mt-2 flex flex-wrap gap-x-5 gap-y-1">
            {BANDS.map((band) => (
              <span key={band} className="flex items-center gap-1.5 text-2xs">
                <span className={cn("h-2 w-2", BAND_STYLE[band].dot)} />
                <span className="text-ink-faint">{band}</span>
                <span className="font-mono tabular-nums text-ink-dim">
                  {counts[band] ?? 0}
                </span>
              </span>
            ))}
          </div>
        </div>

        <div className="px-4 py-3">
          <div className="mb-2 flex items-baseline justify-between">
            <span className="text-2xs uppercase tracking-widest text-ink-faint">
              Score distribution
            </span>
            <span className="font-mono text-2xs tabular-nums text-ink-faint">
              peak {peak}
            </span>
          </div>
          {/* A baseline and end labels, so a bar's height means something. */}
          <div className="flex h-8 items-end gap-px border-b border-line">
            {buckets.map((bucket) => (
              <div
                key={bucket.floor}
                title={`score ${bucket.floor}–${bucket.floor + 9}: ${bucket.count} ${
                  bucket.count === 1 ? "artefact" : "artefacts"
                }`}
                className="group flex flex-1 items-end"
                style={{ height: "100%" }}
              >
                <div
                  className={cn(
                    "w-full transition-opacity group-hover:opacity-80",
                    bucket.count === 0
                      ? "h-px bg-line"
                      : BAND_STYLE[bucketBand(bucket.floor)].dot,
                  )}
                  style={
                    bucket.count === 0
                      ? undefined
                      : { height: `${(bucket.count / peak) * 100}%` }
                  }
                />
              </div>
            ))}
          </div>
          <div className="mt-1 flex justify-between font-mono text-[10px] tabular-nums text-ink-faint">
            <span>0</span>
            <span>40</span>
            <span>60</span>
            <span>80</span>
            <span>100</span>
          </div>
        </div>
      </div>
    </section>
  );
}
