/**
 * The small v2 building blocks the rebuilt screens share (ADR-0038, ADR-0039),
 * drawn with the classes in src/styles/console-v2.css.
 *
 * Two rules live here so no screen can get them wrong on its own:
 *
 * * **A band's colour always travels with its name.** `BandTag` and `tone()`
 *   are how a screen paints severity; each coloured element also carries
 *   `data-band`, which the colour audit (src/test/colour.ts) checks.
 * * **Provenance is a border, never a colour.** `Prov` is solid for verified,
 *   dashed for provisional, dotted for unavailable or unknown.
 */
import { useEffect, useState, type ReactNode } from "react";

import type { Band } from "@/api/types";
import { cn } from "@/lib/format";

/** The class stem for a band's colour: `band-bg-${tone(band)}`, `badge-${...}`. */
export const tone = (band: Band) => band.toLowerCase();

/** False on the first paint, true on the next: bars and gauges grow in. */
export function useGrown(): boolean {
  const [grown, setGrown] = useState(false);
  useEffect(() => {
    const frame = window.requestAnimationFrame(() => setGrown(true));
    return () => window.cancelAnimationFrame(frame);
  }, []);
  return grown;
}

export function PanelHead({ title, sub, right }: { title: ReactNode; sub?: ReactNode; right?: ReactNode }) {
  return (
    <div className="panel-head">
      <div className="min-w-0">
        <h2 className="panel-title">{title}</h2>
        {sub ? <div className="panel-sub">{sub}</div> : null}
      </div>
      {right}
    </div>
  );
}

/** A band, in its band colour: the mockups' `.badge`. */
export function BandTag({ band, testId }: { band: Band; testId?: string }) {
  return (
    <span data-testid={testId} data-band={band} className={`badge badge-${tone(band)}`}>
      {band}
    </span>
  );
}

export type ProvKind = "verified" | "provisional" | "unavailable";

/** A provenance chip: solid, dashed or dotted. Never a colour. */
export function Prov({
  kind,
  children,
  title,
  className,
  testId,
}: {
  kind: ProvKind;
  children: ReactNode;
  title?: string;
  className?: string;
  testId?: string;
}) {
  return (
    <span data-testid={testId} data-provenance={kind} title={title} className={cn("prov", `prov-${kind}`, className)}>
      {children}
    </span>
  );
}

/**
 * "Nothing to show", with the reason: the mockups' dashed `.empty-state`.
 * `testId` / `kind` keep the hooks the honesty tests read.
 */
export function EmptyState({
  testId,
  kind,
  title,
  children,
  action,
}: {
  testId?: string;
  kind?: string;
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div data-testid={testId} data-kind={kind} className="empty-state">
      <p className="empty-title">{title}</p>
      {children ? <div className="empty-text mx-auto max-w-2xl leading-relaxed">{children}</div> : null}
      {action}
    </div>
  );
}

/** A one-line status: a job's progress, or a failed request (the one red). */
export function Notice({
  error = false,
  mono = false,
  testId,
  children,
}: {
  error?: boolean;
  mono?: boolean;
  testId?: string;
  children: ReactNode;
}) {
  return (
    <p data-testid={testId} className={cn("notice", error && "error", mono && "mono")}>
      {children}
    </p>
  );
}
