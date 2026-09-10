/**
 * The strip under the top bar (ADR-0032): what the console is doing, which
 * engine produced this view, how long ago the scan was stored, and its id.
 *
 * It replaces ADR-0018's footer and carries the same auditable facts -- engine
 * versions from `engine_versions` and the provisional count -- in the place
 * the design puts them.
 */
import { useMemo } from "react";

import { cn, relativeAge } from "@/lib/format";
import type { ScanView } from "@/state/inventory";
import { engineLine } from "@/state/presentation";
import { statusOf } from "./status";

export function StatusStrip({ view }: { view: ScanView }) {
  const scan = view.scan;
  const status = statusOf(view);
  const engine = useMemo(
    () => (scan ? engineLine(scan, view.artefacts) : null),
    [scan, view.artefacts],
  );

  return (
    <div className="flex h-9 shrink-0 items-center justify-between gap-4 border-b border-line px-6 font-mono text-[10.5px] uppercase tracking-wider text-ink-faint">
      <div className="flex min-w-0 items-center gap-2">
        <span
          className={cn(
            "h-1.5 w-1.5 shrink-0 rounded-full",
            status.kind === "complete" ? "bg-ink-dim" : status.kind === "error" ? "bg-critical" : "animate-pulse bg-ink-faint",
          )}
          aria-hidden
        />
        <span className="shrink-0 text-ink-dim">{status.label}</span>
        {engine?.parts.map((part) => (
          <span key={part} className="truncate normal-case before:mr-2 before:content-['·']">
            {part}
          </span>
        ))}
        {engine?.warning ? (
          <span className="shrink-0 text-high" title={engine.warning}>
            · engine mismatch
          </span>
        ) : null}
      </div>
      {scan ? (
        <div className="flex shrink-0 items-center gap-4">
          <span title={scan.created_at}>Last scanned {relativeAge(scan.created_at)}</span>
          <span>Scan ID {scan.id.slice(0, 8)}</span>
        </div>
      ) : null}
    </div>
  );
}
