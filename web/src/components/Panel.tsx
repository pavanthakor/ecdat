/**
 * The layout primitives every screen shares, matched to web/design/ (ADR-0032):
 * a page header with the workspace eyebrow and a short rule, rounded cards
 * with an eyebrow and a title inside them, and the badge set.
 *
 * Colour stays semantic (ADR-0031): the only coloured primitive is BandBadge.
 * Verified vs provisional is a solid vs dashed border, never a colour.
 */
import type { AnchorHTMLAttributes, ButtonHTMLAttributes, ReactNode } from "react";

import type { Band } from "@/api/types";
import { BAND_STYLE, cn } from "@/lib/format";

export function ScreenHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="px-6 pb-5 pt-6">
      <div className="eyebrow">Q-orbit / Analysis workspace</div>
      <div className="mt-2 flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-[26px] font-semibold leading-tight tracking-tight text-ink">{title}</h1>
          {subtitle ? (
            <p className="mt-1.5 max-w-3xl text-[13px] leading-relaxed text-ink-dim">{subtitle}</p>
          ) : null}
          <div className="mt-3 h-px w-12 bg-ink-faint" aria-hidden />
        </div>
        {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
    </header>
  );
}

export function Panel({
  eyebrow,
  title,
  meta,
  children,
  className,
  bodyClassName,
}: {
  eyebrow?: ReactNode;
  title?: ReactNode;
  meta?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  const header = eyebrow !== undefined || title !== undefined || meta !== undefined;
  return (
    <section className={cn("min-w-0 rounded-lg border border-line bg-panel", className)}>
      {header ? (
        <div className="flex items-start justify-between gap-4 px-5 pt-4">
          <div className="min-w-0">
            {eyebrow !== undefined ? <div className="eyebrow">{eyebrow}</div> : null}
            {title !== undefined ? (
              <h2 className="mt-1 text-[15px] font-semibold text-ink">{title}</h2>
            ) : null}
          </div>
          {meta !== undefined ? (
            <div className="flex shrink-0 flex-wrap items-center justify-end gap-2 text-2xs text-ink-faint">
              {meta}
            </div>
          ) : null}
        </div>
      ) : null}
      <div className={cn("px-5 pb-5", header ? "pt-4" : "pt-5", bodyClassName)}>{children}</div>
    </section>
  );
}

const BUTTON = {
  default: "border-line bg-panel text-ink hover:border-ink-faint",
  primary: "border-ink bg-ink text-ground hover:bg-white",
  quiet: "border-transparent bg-transparent text-ink hover:text-white",
} as const;

type ButtonVariant = keyof typeof BUTTON;

const BUTTON_BASE =
  "inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-[13px] font-medium transition-colors";

export function Button({
  variant = "default",
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  return (
    <button
      type="button"
      {...props}
      className={cn(BUTTON_BASE, "disabled:cursor-not-allowed disabled:opacity-50", BUTTON[variant], className)}
    />
  );
}

/** A link styled as a button -- for downloads and cross-screen jumps. */
export function LinkButton({
  variant = "default",
  className,
  children,
  ...props
}: AnchorHTMLAttributes<HTMLAnchorElement> & { variant?: ButtonVariant }) {
  return (
    <a {...props} className={cn(BUTTON_BASE, BUTTON[variant], className)}>
      {children}
    </a>
  );
}

const TAG = {
  plain: "border border-line text-ink-dim",
  verified: "border border-ink-faint text-ink-dim",
  provisional: "border border-dashed border-ink-faint/70 text-ink-faint",
  strong: "border border-ink-dim text-ink",
} as const;

/** A small mono caps badge. Provenance by border: solid vs dashed. */
export function Tag({
  children,
  variant = "plain",
  className,
  title,
}: {
  children: ReactNode;
  variant?: keyof typeof TAG;
  className?: string;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={cn(
        "inline-flex items-center whitespace-nowrap rounded-[3px] px-1.5 py-px font-mono text-[9.5px] font-medium uppercase tracking-wider",
        TAG[variant],
        className,
      )}
    >
      {children}
    </span>
  );
}

/** A band, in its band colour. The one coloured badge. */
export function BandBadge({ band }: { band: Band }) {
  const style = BAND_STYLE[band];
  return (
    <span
      className={cn(
        "inline-flex items-center whitespace-nowrap rounded-[3px] border px-1.5 py-px font-mono text-[10px]",
        style.bg,
        style.text,
      )}
    >
      {band}
    </span>
  );
}

/** A rounded status pill on the blue-slate surface, as the design has them. */
export function Pill({ children, title }: { children: ReactNode; title?: string }) {
  return (
    <span
      title={title}
      className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border border-tint-line bg-tint px-3 py-1 text-[10px] font-semibold uppercase tracking-wider text-ink"
    >
      {children}
    </span>
  );
}

export function SkeletonBlock({ className }: { className?: string }) {
  return <div className={cn("animate-pulse rounded-md bg-line/70", className)} />;
}
