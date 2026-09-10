/**
 * The honesty rule's components (ADR-0031).
 *
 * A metric is `computed` -- and then it shows its value AND its basis -- or it
 * is `not-computed`, and then it says so and why. There is no third rendering:
 * no zero standing in for "we did not measure", no skeleton that never
 * resolves, no bar drawn to fill a card. Every screen goes through these, so
 * the rule is enforced in one place and tested in one place.
 */
import type { ReactNode } from "react";

import { cn } from "@/lib/format";
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
      <div className="text-2xs font-medium uppercase tracking-widest text-ink-faint">
        Not computed
      </div>
      <div className="mt-0.5 text-2xs leading-snug text-ink-faint">{reason}</div>
    </div>
  );
}

export function MetricCard({
  id,
  label,
  measured,
  unit,
  sub,
  tone,
}: {
  id: string;
  label: string;
  measured: Measured<number>;
  unit?: string;
  /** Shown under a computed value in place of the basis. */
  sub?: ReactNode;
  tone?: string;
}) {
  return (
    <div
      data-testid={`metric-${id}`}
      data-state={measured.status}
      className="min-w-0 bg-panel px-3 py-2.5"
    >
      <div className="truncate text-2xs uppercase tracking-widest text-ink-faint">
        {label}
      </div>
      {measured.status === "computed" ? (
        <>
          <div
            data-testid="metric-value"
            className={cn("mt-0.5 font-mono text-xl leading-tight tabular-nums text-ink", tone)}
          >
            {measured.value}
            {unit ? <span className="ml-0.5 text-sm text-ink-dim">{unit}</span> : null}
          </div>
          <div
            className="mt-0.5 truncate text-2xs text-ink-faint"
            title={typeof sub === "string" ? sub : measured.basis}
          >
            {sub ?? measured.basis}
          </div>
        </>
      ) : (
        <NotComputed reason={measured.reason} className="mt-1" />
      )}
    </div>
  );
}

/** A screen-level "nothing to show", with the reason and (maybe) a way on. */
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
      className={cn("border border-dashed border-line px-4 py-6", className)}
    >
      <p className="text-xs font-medium text-ink-dim">{title}</p>
      {children ? (
        <div className="mt-1.5 max-w-2xl text-2xs leading-relaxed text-ink-faint">
          {children}
        </div>
      ) : null}
    </div>
  );
}
