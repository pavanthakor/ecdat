/**
 * An (i) affordance.
 *
 * Explanation belongs behind this, not printed beside the control. A console
 * that narrates its own widgets on the main view reads as a tutorial; the
 * people who use one every day already know what the slider does, and the
 * people who do not can hover.
 */
import { Info } from "lucide-react";

export function InfoTip({ label }: { label: string }) {
  return (
    <span
      tabIndex={0}
      role="note"
      aria-label={label}
      title={label}
      className="inline-flex cursor-help items-center text-ink-faint transition-colors hover:text-ink-dim"
    >
      <Info className="h-3 w-3" aria-hidden />
    </span>
  );
}
