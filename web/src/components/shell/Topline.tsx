/**
 * The pieces of the v2 topline (ADR-0038), as the mockups draw them: a
 * breadcrumb over the title, the scoring context as chips under it, and search,
 * status and profile on the right.
 *
 * Kept from ADR-0032: the SCAN crumb is a real `<select>` styled as text, so
 * switching scans stays one click from any screen; search lands on a filtered
 * Inventory; and there is no bell -- nothing in ECDAT raises notifications, and
 * a bell that never rings is a control that lies. The ⌘K hint is real: the
 * shortcut focuses the search box.
 */
import { ChevronDown, Search } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import type { ScanSummary } from "@/api/types";
import { cn, formatDate } from "@/lib/format";
import type { ScanView } from "@/state/inventory";
import { statusOf } from "./status";

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

export function Crumb({ view }: { view: ScanView }) {
  const scan = view.scan;
  return (
    <div className="crumb">
      <span>ECDAT</span>
      <span className="sep">/</span>
      <b className="max-w-[14rem] truncate">{scan?.target.system ?? scan?.target.ref ?? "no system"}</b>
      <span className="sep">/</span>
      <label htmlFor="scan-select" className="sr-only">
        Scan
      </label>
      <span className="flex items-center gap-1">
        <select
          id="scan-select"
          value={scan?.id ?? ""}
          onChange={(event) => view.selectScan(event.target.value)}
        >
          {view.scans.length === 0 ? <option value="">no scans</option> : null}
          {view.scans.map((row) => (
            <option key={row.id} value={row.id}>
              {row.kind === "scan" ? "Scan" : `↳ ${row.kind}`} {row.id.slice(0, 8)} · {formatDate(row.created_at)}
            </option>
          ))}
        </select>
        <ChevronDown className="pointer-events-none h-3 w-3" aria-hidden />
      </span>
    </div>
  );
}

/** The scoring context. An unrecorded one is a dashed chip that says so. */
export function ContextChips({ scan }: { scan: ScanSummary | null }) {
  const chips: [string, string | null][] = [
    ["Sector", scan?.sector ? (SECTOR_LABEL[scan.sector] ?? scan.sector) : null],
    ["Exposure", scan?.exposure ? (EXPOSURE_LABEL[scan.exposure] ?? scan.exposure) : null],
    ["Data class", scan?.target.data_class ?? null],
  ];
  return (
    <div className="chip-row">
      {chips.map(([label, value]) =>
        value ? (
          <span key={label} className="chip">
            {label} · {value}
          </span>
        ) : (
          <span key={label} className="chip unrecorded" title="Not recorded on this scan">
            {label} not recorded
          </span>
        ),
      )}
    </div>
  );
}

const MAC = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.userAgent);

export function SearchBox({ onSearch }: { onSearch: (query: string) => void }) {
  const [query, setQuery] = useState("");
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const focus = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        input.current?.focus();
        input.current?.select();
      }
    };
    document.addEventListener("keydown", focus);
    return () => document.removeEventListener("keydown", focus);
  }, []);

  return (
    <form
      role="search"
      onSubmit={(event) => {
        event.preventDefault();
        onSearch(query.trim());
      }}
    >
      <label className="search-box">
        <Search className="h-3.5 w-3.5 shrink-0" aria-hidden />
        <input
          ref={input}
          type="search"
          aria-label="Search artefacts"
          placeholder="Search artefacts"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
        <kbd title="Focus search">{MAC ? "⌘K" : "Ctrl K"}</kbd>
      </label>
    </form>
  );
}

/** What the console is doing. Neutral; a failed request is the one red state. */
export function StatusChip({ view }: { view: ScanView }) {
  const status = statusOf(view);
  return (
    <span
      data-testid="status"
      data-status={status.kind}
      title={status.kind === "error" ? (view.error ?? undefined) : undefined}
      className={cn("status-chip", status.kind === "error" && "error")}
    >
      <span
        className={cn(
          "dot",
          status.kind === "error" && "error",
          status.kind !== "complete" && status.kind !== "error" && "busy",
        )}
        aria-hidden
      />
      {status.label}
    </span>
  );
}
