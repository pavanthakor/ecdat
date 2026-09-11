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
      <div className="not-computed-label">Not computed</div>
      <div className="not-computed-reason">{reason}</div>
    </div>
  );
}

/**
 * The v2 stat card (ADR-0038): icon and label, then the number and a small
 * pill. The mockup's pill is a delta ("+6", in red or green); nothing computes
 * a delta, so here it is the BASIS, in neutral ink, with the full basis on
 * hover.
 */
export function MetricCard({
  id,
  label,
  measured,
  unit,
  pad = false,
  icon,
  note,
}: {
  id: string;
  label: string;
  measured: Measured<number>;
  unit?: string;
  /** Two-digit counts, as the design shows them ("08"). */
  pad?: boolean;
  icon?: ReactNode;
  /** A short form of the basis for the pill. Defaults to the basis. */
  note?: string;
}) {
  return (
    <div data-testid={`metric-${id}`} data-state={measured.status} className="stat-card">
      <div className="stat-top">
        {icon ? (
          <span className="stat-icon" aria-hidden>
            {icon}
          </span>
        ) : null}
        <span className="stat-label">{label}</span>
      </div>
      {measured.status === "computed" ? (
        <div className="stat-bottom">
          <span data-testid="metric-value" className="stat-num">
            {pad ? pad2(measured.value) : measured.value}
            {unit ?? null}
          </span>
          <span className="stat-delta" title={measured.basis}>
            {note ?? measured.basis}
          </span>
        </div>
      ) : (
        <NotComputed reason={measured.reason} />
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
