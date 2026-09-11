/** An unknown route says so. It does not quietly render the Overview instead. */
import { hrefFor } from "@/lib/router";

export function NotFoundScreen({ path }: { path: string }) {
  return (
    <div className="content">
      <div data-testid="route-not-found" className="empty-state flex max-w-xl items-start gap-4 text-left">
        <span className="brand-mark opacity-40" aria-hidden>
          E
        </span>
        <div>
          <p className="empty-title">
            No screen at <code className="mono">#/{path}</code>
          </p>
          <p className="empty-text">
            The link may be from an older build, or mistyped.{" "}
            <a href={hrefFor("overview")} className="text-ink-dim underline">
              Back to Overview
            </a>
          </p>
        </div>
      </div>
    </div>
  );
}
