/**
 * The strip a reader lands on: what is in this estate, and how bad is it.
 *
 * Every number here comes off the DENORMALISED scan row (ADR-0016) rather than
 * from counting the CBOM in the browser. Two reasons: the row is what the
 * store recorded at scan time, so the strip cannot disagree with the document
 * it summarises; and counting an estate-sized document per render is the
 * O(scans x document) mistake the API stopped making.
 */
import { Boxes, GitCompareArrows, Layers, TriangleAlert } from "lucide-react";
import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import type { Artefact, Band, ScanSummary } from "@/api/types";
import { BANDS } from "@/api/types";
import { BAND_STYLE, cn } from "@/lib/format";

interface Props {
  scan: ScanSummary | null;
  artefacts: Artefact[];
}

const BAND_FILL: Record<Band, string> = {
  Critical: "#f43f5e",
  High: "#f59e0b",
  Medium: "#eab308",
  Low: "#475569",
};

function Metric({
  label,
  value,
  sub,
  icon: Icon,
  tone,
}: {
  label: string;
  value: string | number;
  sub?: string;
  icon: typeof Boxes;
  tone?: string;
}) {
  return (
    <div className="flex items-start gap-2.5 border-r border-line px-4 py-2.5 last:border-r-0">
      <Icon className="mt-0.5 h-3.5 w-3.5 shrink-0 text-ink-faint" aria-hidden />
      <div className="min-w-0">
        <div className="text-2xs uppercase tracking-widest text-ink-faint">
          {label}
        </div>
        <div
          className={cn(
            "font-mono text-xl leading-tight tabular-nums text-ink",
            tone,
          )}
        >
          {value}
        </div>
        {sub ? (
          <div className="mt-0.5 truncate text-2xs text-ink-faint">{sub}</div>
        ) : null}
      </div>
    </div>
  );
}

/**
 * Coverage, told honestly.
 *
 * `null` means the row predates the column and we cannot say what ran; `[]`
 * means we can, and nothing did (ADR-0016). Rendering both as "none" would
 * turn "never looked for binaries" into "binaries were clean", which is the
 * exact confusion the column was added to end.
 */
function coverageLabel(scanners: ScanSummary["scanners_ran"]): {
  value: string;
  sub: string;
} {
  if (scanners === null) return { value: "unknown", sub: "not recorded for this scan" };
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

  // Score distribution in 10-point buckets, coloured by the band each bucket
  // falls in -- so the shape of the estate is readable at a glance without a
  // legend.
  const buckets = Array.from({ length: 10 }, (_, index) => ({
    label: `${index * 10}-${index * 10 + 9}`,
    floor: index * 10,
    count: 0,
  }));
  for (const artefact of artefacts) {
    const index = Math.min(9, Math.floor(artefact.score / 10));
    buckets[index].count += 1;
  }
  const bucketBand = (floor: number): Band =>
    floor >= 80 ? "Critical" : floor >= 60 ? "High" : floor >= 40 ? "Medium" : "Low";

  return (
    <section className="border-b border-line bg-panel">
      <div className="grid grid-cols-2 divide-x divide-line lg:grid-cols-4">
        <Metric
          label="Artefacts"
          value={scan.component_count}
          sub={`${scan.target.kind} · ${scan.target.ref}`}
          icon={Boxes}
        />
        <Metric
          label="Max score"
          value={scan.max_score}
          sub={`${counts.Critical ?? 0} critical · ${counts.High ?? 0} high`}
          icon={TriangleAlert}
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
          icon={GitCompareArrows}
          tone={driftTotal > 0 ? "text-high" : undefined}
        />
        <Metric
          label="Scanners"
          value={coverage.value}
          sub={coverage.sub}
          icon={Layers}
        />
      </div>

      <div className="grid grid-cols-1 gap-px border-t border-line bg-line lg:grid-cols-[1fr_20rem]">
        <div className="bg-panel px-4 py-3">
          <div className="mb-2 flex items-baseline justify-between">
            <span className="text-2xs uppercase tracking-widest text-ink-faint">
              Band distribution
            </span>
            <span className="font-mono text-2xs text-ink-faint">
              {total} scored
            </span>
          </div>
          {/* A segmented bar rather than a chart: four values at this density
              read better as exact pixel widths than as a plotted series. */}
          <div className="flex h-2.5 w-full overflow-hidden border border-line">
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
                <span className="text-ink-dim">{band}</span>
                <span className="font-mono tabular-nums text-ink">
                  {counts[band] ?? 0}
                </span>
              </span>
            ))}
          </div>
        </div>

        <div className="bg-panel px-4 py-3">
          <div className="mb-1 text-2xs uppercase tracking-widest text-ink-faint">
            Score distribution
          </div>
          <div className="h-[52px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={buckets}
                margin={{ top: 2, right: 0, bottom: 0, left: 0 }}
                barCategoryGap={2}
              >
                <XAxis dataKey="floor" hide />
                <YAxis hide />
                <Tooltip
                  cursor={{ fill: "rgba(148,163,184,0.08)" }}
                  contentStyle={{
                    background: "#0b1220",
                    border: "1px solid #1e293b",
                    borderRadius: 0,
                    fontSize: 11,
                    padding: "4px 8px",
                  }}
                  labelFormatter={(floor) => `score ${floor}–${Number(floor) + 9}`}
                  formatter={(value: number) => [value, "components"]}
                />
                <Bar dataKey="count" isAnimationActive={false}>
                  {buckets.map((bucket) => (
                    <Cell
                      key={bucket.floor}
                      fill={BAND_FILL[bucketBand(bucket.floor)]}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </section>
  );
}
