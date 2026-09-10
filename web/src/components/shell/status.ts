/** What the console is doing right now -- shared by the top-bar pill and the strip. */
import type { ScanView } from "@/state/inventory";

export type StatusKind = "loading" | "rescoring" | "error" | "no-scan" | "complete";

export function statusOf(view: ScanView): { kind: StatusKind; label: string } {
  if (view.loading) return { kind: "loading", label: "Loading" };
  if (view.rescoring) return { kind: "rescoring", label: "Re-scoring" };
  if (view.error) return { kind: "error", label: "Error" };
  if (!view.scan) return { kind: "no-scan", label: "No scan" };
  return { kind: "complete", label: "Analysis complete" };
}
