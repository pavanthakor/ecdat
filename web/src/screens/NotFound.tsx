/** An unknown route says so. It does not quietly render the Overview instead. */
import { QOrbitMark } from "@/components/shell/Logo";
import { hrefFor } from "@/lib/router";

export function NotFoundScreen({ path }: { path: string }) {
  return (
    <div className="px-6 py-8">
      <div
        data-testid="route-not-found"
        className="flex max-w-xl items-start gap-4 rounded-lg border border-dashed border-line bg-panel px-5 py-5"
      >
        <QOrbitMark tone="muted" className="h-8 w-8 shrink-0" title="Q-orbit (inactive)" />
        <div>
          <p className="text-[14px] font-medium text-ink">
            No screen at <code className="font-mono">#/{path}</code>
          </p>
          <p className="mt-1 text-[12px] text-ink-faint">
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
