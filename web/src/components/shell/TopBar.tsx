/**
 * The top bar, as the design has it: SYSTEM / SCAN breadcrumb, the scoring
 * context as bordered chips, search, a status pill and the operator menu.
 *
 * The SCAN crumb is a real `<select>` styled as text, so switching scans stays
 * one click from anywhere. Search lands on a filtered Inventory. There is no
 * bell: nothing in ECDAT raises notifications, and a bell that never rings is
 * a control that lies (ADR-0032).
 */
import { ChevronDown, Search } from "lucide-react";
import { useState } from "react";

import { cn, formatDate } from "@/lib/format";
import type { ScanView } from "@/state/inventory";
import { statusOf } from "./status";
import { UserMenu } from "./UserMenu";

const SECTOR_LABEL: Record<string, string> = {
  bfsi: "Financial services",
  government: "Government",
  strategic: "Strategic",
  defence: "Defence",
  power: "Power",
  telecom: "Telecom",
  transport: "Transport",
  other: "Other",
};

const EXPOSURE_LABEL: Record<string, string> = {
  internet: "Internet-facing",
  internal: "Internal",
  build: "Build-time",
  unknown: "Unknown",
};

function Chip({ label, value }: { label: string; value: string | null }) {
  return (
    <span className="flex items-center gap-1.5 whitespace-nowrap rounded-md border border-line px-2 py-1 text-[10px]">
      <span className="font-semibold uppercase tracking-wider text-ink-faint">{label}</span>
      <span className="font-medium text-ink">{value ?? "not recorded"}</span>
    </span>
  );
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
    <header className="flex h-16 shrink-0 items-center gap-3 border-b border-line bg-ground px-6">
      <div className="flex min-w-0 items-center gap-2 text-[13px]">
        <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-ink-faint">System</span>
        <span className="max-w-[10rem] truncate text-ink">
          {scan?.target.system ?? scan?.target.ref ?? "—"}
        </span>
        <span className="text-ink-faint">/</span>
        <label
          htmlFor="scan-select"
          className="text-[10px] font-semibold uppercase tracking-[0.14em] text-ink-faint"
        >
          Scan
        </label>
        <span className="relative flex min-w-0 items-center">
          <select
            id="scan-select"
            value={scan?.id ?? ""}
            onChange={(event) => view.selectScan(event.target.value)}
            className="max-w-[15rem] cursor-pointer appearance-none truncate bg-transparent pr-5 text-[13px] text-ink focus:outline-none"
          >
            {view.scans.length === 0 ? <option value="">no scans</option> : null}
            {view.scans.map((row) => (
              <option key={row.id} value={row.id} className="bg-panel">
                {row.kind === "scan" ? "" : "↳ "}
                {formatDate(row.created_at)} · {row.id.slice(0, 8)}
                {row.kind === "scan" ? "" : ` · ${row.kind}`}
              </option>
            ))}
          </select>
          <ChevronDown className="pointer-events-none absolute right-0 h-3.5 w-3.5 text-ink-faint" aria-hidden />
        </span>
      </div>

      <div className="hidden items-center gap-2 lg:flex">
        <Chip label="Sector" value={scan?.sector ? (SECTOR_LABEL[scan.sector] ?? scan.sector) : null} />
        <Chip label="Exposure" value={scan?.exposure ? (EXPOSURE_LABEL[scan.exposure] ?? scan.exposure) : null} />
        <Chip label="Data class" value={scan?.target.data_class ?? null} />
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
          <Search className="pointer-events-none absolute left-3 h-4 w-4 text-ink-faint" aria-hidden />
          <input
            type="search"
            aria-label="Search artefacts"
            placeholder="Search artefacts"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            className={cn(
              "h-9 w-52 rounded-md border border-line bg-panel pl-9 pr-3 text-[13px] text-ink xl:w-64",
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
          "flex h-7 items-center gap-1.5 whitespace-nowrap rounded-full border px-3 text-[10px] font-semibold uppercase tracking-wider",
          status.kind === "error" ? "border-critical/50 text-critical" : "border-tint-line bg-tint text-ink",
        )}
      >
        <span
          className={cn(
            "h-1.5 w-1.5 rounded-full",
            status.kind === "complete" && "bg-ink",
            status.kind === "error" && "bg-critical",
            status.kind !== "complete" && status.kind !== "error" && "animate-pulse bg-ink-faint",
          )}
          aria-hidden
        />
        {status.label}
      </span>

      <UserMenu />
    </header>
  );
}
