/**
 * The Q-orbit mark (ADR-0031).
 *
 * One tilted elliptical ring -- the Q's bowl, and an orbit -- with a small
 * filled node on the ring at lower right. The Q's tail is a short stroke
 * through that node, crossing the ring: the node is at once the satellite on
 * the orbit and the joint where the tail leaves the letter, which is what lets
 * the mark read as both.
 *
 * Monoline, 1.75 units on a 32-unit grid (about 1.5px at 28px). No gradient,
 * no glow. `brand` is amber on the dark shell; `muted` is slate, used when the
 * console has no analysis loaded. The node position is computed, not eyeballed:
 * the point at t = 60 degrees on an 11 x 9.5 ellipse about (16, 16), rotated
 * -20 degrees, is (23.98, 21.85), and the tail runs through it at 45 degrees.
 */
import { cn } from "@/lib/format";

export type MarkTone = "brand" | "muted";

export function QOrbitMark({
  tone = "brand",
  className,
  title = "Q-orbit",
}: {
  tone?: MarkTone;
  className?: string;
  title?: string;
}) {
  const stroke = tone === "brand" ? "stroke-brand" : "stroke-ink-faint";
  const fill = tone === "brand" ? "fill-brand" : "fill-ink-faint";
  return (
    <svg
      viewBox="0 0 32 32"
      role="img"
      aria-label={title}
      data-tone={tone}
      className={cn("transition-colors", className)}
    >
      <ellipse
        cx="16"
        cy="16"
        rx="11"
        ry="9.5"
        transform="rotate(-20 16 16)"
        fill="none"
        strokeWidth="1.75"
        className={stroke}
      />
      <line
        x1="21.29"
        y1="19.16"
        x2="27.23"
        y2="25.1"
        strokeWidth="1.75"
        strokeLinecap="round"
        className={stroke}
      />
      <circle cx="23.98" cy="21.85" r="2.3" className={fill} />
    </svg>
  );
}

export function QOrbitLogo({ tone = "brand" }: { tone?: MarkTone }) {
  return (
    <div className="flex items-center gap-2.5">
      <QOrbitMark tone={tone} className="h-7 w-7 shrink-0" />
      <div className="leading-none">
        <div className="text-[15px] font-semibold tracking-tight text-ink">Q-orbit</div>
        <div className="mt-1 text-[8.5px] font-medium uppercase tracking-[0.24em] text-ink-faint">
          Security Console
        </div>
      </div>
    </div>
  );
}
