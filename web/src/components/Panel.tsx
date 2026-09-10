/**
 * The layout primitives every screen shares: a screen header, a panel, a
 * button and a tag. Square corners, hairline borders, flat fills -- the
 * console's whole vocabulary, in one place so screens cannot drift apart.
 */
import type { ButtonHTMLAttributes, ReactNode } from "react";

import { cn } from "@/lib/format";

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
    <div className="flex flex-wrap items-end justify-between gap-3 border-b border-line bg-ground px-5 pb-3 pt-4">
      <div className="min-w-0">
        <h1 className="text-lg font-semibold leading-tight tracking-tight text-ink">{title}</h1>
        {subtitle ? (
          <p className="mt-1 max-w-3xl text-2xs leading-relaxed text-ink-faint">{subtitle}</p>
        ) : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function Panel({
  title,
  meta,
  children,
  className,
  bodyClassName,
  testId,
}: {
  title: ReactNode;
  meta?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  testId?: string;
}) {
  return (
    <section data-testid={testId} className={cn("min-w-0 border border-line bg-panel", className)}>
      <header className="flex items-center justify-between gap-3 border-b border-line px-3 py-1.5">
        <h2 className="truncate text-2xs font-semibold uppercase tracking-widest text-ink-faint">
          {title}
        </h2>
        {meta ? <div className="shrink-0 text-2xs text-ink-faint">{meta}</div> : null}
      </header>
      <div className={cn("p-3", bodyClassName)}>{children}</div>
    </section>
  );
}

export function Button({
  variant = "default",
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "default" | "primary" | "quiet" }) {
  return (
    <button
      type="button"
      {...props}
      className={cn(
        "inline-flex items-center gap-1.5 border px-2.5 py-1 text-2xs font-medium transition-colors",
        "disabled:cursor-not-allowed disabled:opacity-50",
        variant === "primary" && "border-ink-dim bg-raised text-ink hover:border-ink hover:bg-line",
        variant === "default" && "border-line bg-panel text-ink-dim hover:border-ink-faint hover:text-ink",
        variant === "quiet" && "border-transparent text-ink-faint hover:text-ink",
        className,
      )}
    />
  );
}

/** A link styled as a button -- for downloads and cross-screen jumps. */
export function LinkButton({
  className,
  children,
  ...props
}: React.AnchorHTMLAttributes<HTMLAnchorElement>) {
  return (
    <a
      {...props}
      className={cn(
        "inline-flex items-center gap-1.5 border border-line bg-panel px-2.5 py-1 text-2xs font-medium text-ink-dim transition-colors hover:border-ink-faint hover:text-ink",
        className,
      )}
    >
      {children}
    </a>
  );
}

/**
 * A small uppercase tag. `verified` is solid and `provisional` is dashed --
 * provenance by border, never colour (ADR-0018).
 */
export function Tag({
  children,
  variant = "plain",
  className,
  title,
}: {
  children: ReactNode;
  variant?: "plain" | "verified" | "provisional" | "strong";
  className?: string;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={cn(
        "inline-flex items-center whitespace-nowrap px-1.5 py-px text-[9.5px] font-medium uppercase tracking-wider",
        variant === "plain" && "border border-line text-ink-faint",
        variant === "verified" && "border border-ink-faint/70 bg-raised text-ink-dim",
        variant === "provisional" && "border border-dashed border-ink-faint/60 text-ink-faint",
        variant === "strong" && "border-2 border-ink-dim text-ink",
        className,
      )}
    >
      {children}
    </span>
  );
}

export function SkeletonBlock({ className }: { className?: string }) {
  return <div className={cn("animate-pulse bg-line/70", className)} />;
}
