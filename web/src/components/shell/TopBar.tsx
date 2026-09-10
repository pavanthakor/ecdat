/**
 * The top bar: WHICH estate and scan, in what context, and is it ready.
 *
 * The breadcrumb names the system and the scan; the chips are the scoring
 * context the row recorded (quiet label + value, not alerts); the status says
 * what the console is doing right now; search lands on a filtered Inventory.
 * The user menu is cosmetic -- see UserMenu.
 */
import { ChevronRight, Search } from "lucide-react";
import { useState } from "react";

import { cn, formatDate } from "@/lib/format";
import type { ScanView } from "@/state/inventory";
import { QOrbitLogo } from "./Logo";
import { UserMenu } from "./UserMenu";

function MetaChip({ label, value }: { label: string; value: string | null }) {
  return (
    <span className="flex items-baseline gap-1.5 whitespace-nowrap">
      <span className="text-[10px] uppercase tracking-wider text-ink-faint">{label}</span>
      <span className="font-mono text-2xs text-ink-dim">{value ?? "—"}</span>
    </span>
  );
}

type StatusKind = "loading" | "rescoring" | "error" | "no-scan" | "complete";

function statusOf(view: ScanView): { kind: StatusKind; label: string } {
  if (view.loading) return { kind: "loading", label: "Loading" };
  if (view.rescoring) return { kind: "rescoring", label: "Re-scoring" };
  if (view.error) return { kind: "error", label: "Error" };
  if (!view.scan) return { kind: "no-scan", label: "No scan" };
  return { kind: "complete", label: "Analysis complete" };
}

export function TopBar({
  view,
  onSearch,
}: {
  view: ScanView;
  onSearch: (query: string) => void;
}) {
  const [query, setQuery] = useState("");
  const status = statusOf(view);
  const scan = view.scan;

  return (
    <header className="flex h-12 shrink-0 items-center border-b border-line bg-panel">
      <div className="flex h-full w-52 shrink-0 items-center border-r border-line px-4">
        <QOrbitLogo tone={status.kind === "complete" || status.kind === "rescoring" ? "brand" : "muted"} />
      </div>

      <div className="flex min-w-0 flex-1 items-center gap-5 px-4">
        <div className="flex min-w-0 items-center gap-2 text-2xs">
          <span className="text-[10px] uppercase tracking-wider text-ink-faint">System</span>
          <span className="max-w-[10rem] truncate font-medium text-ink">
            {scan?.target.system ?? scan?.target.ref ?? "—"}
          </span>
          <ChevronRight className="h-3 w-3 shrink-0 text-ink-faint" aria-hidden />
          <label
            htmlFor="scan-select"
            className="text-[10px] uppercase tracking-wider text-ink-faint"
          >
            Scan
          </label>
          <select
            id="scan-select"
            value={scan?.id ?? ""}
            onChange={(event) => view.selectScan(event.target.value)}
            className={cn(
              "h-7 max-w-[17rem] border border-line bg-ground px-1.5 font-mono text-2xs text-ink-dim",
              "focus:border-ink-faint focus:outline-none",
            )}
          >
            {view.scans.length === 0 ? <option value="">no scans</option> : null}
            {view.scans.map((row) => (
              <option key={row.id} value={row.id}>
                {row.kind === "scan" ? "" : "↳ "}
                {row.id.slice(0, 8)} · {row.kind} · {formatDate(row.created_at)}
              </option>
            ))}
          </select>
        </div>

        <div className="hidden items-center gap-4 xl:flex">
          <MetaChip label="Sector" value={scan?.sector ?? null} />
          <MetaChip label="Exposure" value={scan?.exposure ?? null} />
          <MetaChip label="Data" value={scan?.target.data_class ?? null} />
        </div>

        <form
          role="search"
          className="ml-auto"
          onSubmit={(event) => {
            event.preventDefault();
            onSearch(query.trim());
          }}
        >
          <label className="relative flex items-center">
            <Search className="pointer-events-none absolute left-2 h-3 w-3 text-ink-faint" aria-hidden />
            <input
              type="search"
              aria-label="Search artefacts"
              placeholder="Search artefacts, bom-refs, paths"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              className={cn(
                "h-7 w-60 border border-line bg-ground pl-7 pr-2 text-xs text-ink",
                "placeholder:text-ink-faint focus:border-ink-faint focus:outline-none",
              )}
            />
          </label>
        </form>

        <span
          data-testid="status"
          data-status={status.kind}
          title={status.kind === "error" ? (view.error ?? undefined) : undefined}
          className={cn(
            "flex items-center gap-1.5 whitespace-nowrap border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider",
            status.kind === "error"
              ? "border-critical/50 text-critical"
              : status.kind === "complete"
                ? "border-line text-ink-dim"
                : "border-dashed border-line text-ink-faint",
          )}
        >
          <span
            className={cn(
              "h-1.5 w-1.5",
              status.kind === "complete"
                ? "bg-ink-dim"
                : status.kind === "error"
                  ? "bg-critical"
                  : "animate-pulse bg-ink-faint",
            )}
            aria-hidden
          />
          {status.label}
        </span>

        <UserMenu />
      </div>
    </header>
  );
}
