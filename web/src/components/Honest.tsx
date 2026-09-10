/**
 * The honesty rule's components (ADR-0031), in the design's card shape
 * (ADR-0032).
 *
 * A metric is `computed` -- and then it shows its value AND its basis -- or it
 * is `not-computed`, and then it says so and why. There is no third rendering:
 * no zero standing in for "we did not measure", no skeleton that never
 * resolves, no bar drawn to fill a card. The design's sample figures are a
 * mockup; where the backend computes nothing, this is what renders instead.
 */
import type { ReactNode } from "react";

import { cn, pad2 } from "@/lib/format";
import type { Measured } from "@/state/metrics";

export function NotComputed({
  reason,
  className,
}: {
  reason: string;
  className?: string;
}) {
  return (
    <div className={cn("min-w-0", className)}>
      <div className="font-mono text-[10.5px] font-medium uppercase tracking-wider text-ink-faint">
        Not computed
      </div>
      <div className="mt-0.5 text-[11.5px] leading-snug text-ink-faint">{reason}</div>
    </div>
  );
}

export function MetricCard({
  id,
  label,
  measured,
  unit,
  pad = false,
}: {
  id: string;
  label: string;
  measured: Measured<number>;
  unit?: string;
  /** Two-digit counts, as the design shows them ("08"). */
  pad?: boolean;
}) {
  return (
    <div
      data-testid={`metric-${id}`}
      data-state={measured.status}
      className="min-w-0 rounded-lg border border-line bg-panel px-4 pb-3.5 pt-3"
    >
      <div className="eyebrow truncate">{label}</div>
      {measured.status === "computed" ? (
        <>
          <div
            data-testid="metric-value"
            className="mt-2.5 text-[26px] font-semibold leading-none tabular-nums text-ink"
          >
            {pad ? pad2(measured.value) : measured.value}
            {unit ? <span className="text-[22px]">{unit}</span> : null}
          </div>
          <div className="mt-2.5 truncate text-[11.5px] text-ink-faint" title={measured.basis}>
            {measured.basis}
          </div>
        </>
      ) : (
        <NotComputed reason={measured.reason} className="mt-2.5" />
      )}
    </div>
  );
}

/** A "nothing to show", with the reason and (maybe) a way on. */
export function EmptyPanel({
  testId,
  kind,
  title,
  children,
  className,
}: {
  testId?: string;
  kind?: string;
  title: string;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <div
      data-testid={testId}
      data-kind={kind}
      className={cn("rounded-lg border border-dashed border-line px-5 py-6", className)}
    >
      <p className="text-[13px] font-medium text-ink-dim">{title}</p>
      {children ? (
        <div className="mt-1.5 max-w-2xl text-[12px] leading-relaxed text-ink-faint">{children}</div>
      ) : null}
    </div>
  );
}
