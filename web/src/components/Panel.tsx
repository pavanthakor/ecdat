/**
 * The layout primitives every screen shares. ScreenHeader is the v2 topline
 * (ADR-0038); the cards and badges below are the ADR-0032 set, which screens
 * not yet rebuilt on the v2 classes still use.
 *
 * Colour stays semantic (ADR-0031): the only coloured primitive is BandBadge.
 * Verified vs provisional is a solid vs dashed border, never a colour.
 */
import type { AnchorHTMLAttributes, ButtonHTMLAttributes, ReactNode } from "react";

import type { Band } from "@/api/types";
import { useConsole } from "@/components/shell/console";
import { ContextChips, Crumb, SearchBox, StatusChip } from "@/components/shell/Topline";
import { UserMenu } from "@/components/shell/UserMenu";
import { BAND_STYLE, cn } from "@/lib/format";

/**
 * The v2 topline: crumb, title and context chips on the left; search, status,
 * profile and the page's own actions on the right. Inside the console it draws
 * the frame; rendered on its own it is just the title and the actions.
 */
export function ScreenHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: ReactNode;
  actions?: ReactNode;
}) {
  const frame = useConsole();
  return (
    <header className="topline screen-head">
      <div className="min-w-0">
        {frame ? <Crumb view={frame.view} /> : null}
        <h1 className="page-title">{title}</h1>
        {subtitle ? <p className="page-sub">{subtitle}</p> : null}
        {frame ? <ContextChips scan={frame.view.scan} /> : null}
      </div>
      <div className="top-right">
        {frame ? (
          <>
            <SearchBox onSearch={frame.onSearch} />
            <StatusChip view={frame.view} />
            <UserMenu />
          </>
        ) : null}
        {actions}
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
  testId,
}: {
  children: ReactNode;
  variant?: keyof typeof TAG;
  className?: string;
  title?: string;
  testId?: string;
}) {
  return (
    <span
      data-testid={testId}
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
      data-testid="band-pill"
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
