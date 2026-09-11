/**
 * COMPARE SCANS -- what changed between two stored scans (ADR-0031), laid out
 * as web/design/ has it (ADR-0032): A-vs-B selectors in the header, four count
 * cards, and one "changed evidence" list with a NEW / CHANGED / RESOLVED tag
 * per row.
 *
 * Read from `GET /scans/{base}/compare/{head}`, joined on the content-addressed
 * bom-ref; the console computes no diff of its own. The default pair comes from
 * the store's links, and with no such pair the screen asks for two scans
 * instead of inventing a baseline. Counts are neutral ink: the design paints
 * them red and orange, and colour here means a band (ADR-0031).
 */
import { ChevronDown, ChevronRight, Download } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { compareScans } from "@/api/client";
import type { CompareChange, CompareResponse, ScanSummary } from "@/api/types";
import { EmptyPanel } from "@/components/Honest";
import { Button, Panel, ScreenHeader, SkeletonBlock, Tag } from "@/components/Panel";
import { downloadText } from "@/lib/download";
import { formatDate } from "@/lib/format";
import { hrefFor } from "@/lib/router";
import { defaultComparison } from "@/state/metrics";
import { useRemote } from "@/state/remote";

interface DiffRow {
  key: string;
  name: string;
  what: string;
  value: string;
  detail?: string;
  tag: "New" | "Changed" | "Resolved";
  ref: string | null;
}

function changeRow(change: CompareChange): DiffRow {
  const verdict = change.fields.filter((field) => field !== "evidence");
  const moved = verdict
    .map((field) => {
      const key = field as keyof CompareChange["before"];
      return `${field} ${String(change.before[key] ?? "—")} → ${String(change.after[key] ?? "—")}`;
    })
    .join(" · ");
  const evidence = change.fields.includes("evidence")
    ? `+${change.evidence_added.length} / −${change.evidence_removed.length} sightings`
    : "";
  return {
    key: `changed:${change.bom_ref}`,
    name: change.name,
    what: verdict.length > 0 ? `${verdict.join(", ")} changed` : "Evidence changed",
    value: [moved, evidence].filter(Boolean).join(" · "),
    detail: [...change.evidence_removed.map((e) => `− ${e}`), ...change.evidence_added.map((e) => `+ ${e}`)].join("\n"),
    tag: "Changed",
    ref: change.bom_ref,
  };
}

function diffRows(data: CompareResponse): DiffRow[] {
  return [
    ...data.new.map((entry) => ({
      key: `new:${entry.bom_ref}`,
      name: entry.name,
      what: "New artefact",
      value: `${entry.band ?? "—"} · score ${entry.score ?? "—"}`,
      tag: "New" as const,
      ref: entry.bom_ref,
    })),
    ...data.changed.map(changeRow),
    ...data.drift_introduced.map((drift) => ({
      key: `drift+:${drift.bom_ref}:${drift.kind}:${drift.declared}`,
      name: drift.name,
      what: `Drift introduced · ${drift.kind}`,
      value: `${drift.declared} ≠ ${drift.observed}`,
      detail: drift.cause,
      tag: "New" as const,
      ref: drift.bom_ref,
    })),
    ...data.resolved.map((entry) => ({
      key: `resolved:${entry.bom_ref}`,
      name: entry.name,
      what: "No longer found",
      value: `${entry.band ?? "—"} · score ${entry.score ?? "—"}`,
      tag: "Resolved" as const,
      ref: null,
    })),
    ...data.drift_resolved.map((drift) => ({
      key: `drift-:${drift.bom_ref}:${drift.kind}:${drift.declared}`,
      name: drift.name,
      what: `Drift resolved · ${drift.kind}`,
      value: `${drift.declared} ≠ ${drift.observed}`,
      tag: "Resolved" as const,
      ref: null,
    })),
  ];
}

function ScanPicker({
  label,
  value,
  scans,
  onChange,
}: {
  label: string;
  value: string;
  scans: ScanSummary[];
  onChange: (id: string) => void;
}) {
  return (
    <label className="relative flex items-center rounded-md border border-line bg-panel py-1.5 pl-3 pr-7 text-[13px]">
      <span className="mr-2 text-[10px] font-semibold uppercase tracking-wider text-ink-faint">{label}</span>
      <select
        aria-label={`${label} scan`}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="max-w-[13rem] cursor-pointer appearance-none truncate bg-transparent text-ink focus:outline-none"
      >
        <option value="" className="bg-panel">
          choose a scan
        </option>
        {scans.map((scan) => (
          <option key={scan.id} value={scan.id} className="bg-panel">
            {scan.id.slice(0, 8)} · {formatDate(scan.created_at)}
            {scan.kind === "scan" ? "" : ` · ${scan.kind}`}
          </option>
        ))}
      </select>
      <ChevronDown className="pointer-events-none absolute right-2 h-3.5 w-3.5 text-ink-faint" aria-hidden />
    </label>
  );
}

export function CompareScreen({
  scans,
  current,
}: {
  scans: ScanSummary[];
  current: ScanSummary | null;
}) {
  const initial = useMemo(
    () => (current ? defaultComparison(scans, current) : { base: null, head: null }),
    [scans, current],
  );
  const [baseId, setBaseId] = useState<string>(initial.base?.id ?? "");
  const [headId, setHeadId] = useState<string>(initial.head?.id ?? "");
  useEffect(() => {
    setBaseId(initial.base?.id ?? "");
    setHeadId(initial.head?.id ?? "");
  }, [initial]);

  const ready = baseId !== "" && headId !== "" && baseId !== headId;
  const result = useRemote(ready ? `compare:${baseId}:${headId}` : null, () => compareScans(baseId, headId));
  const data = result.data;
  const rows = useMemo(() => (data ? diffRows(data) : []), [data]);
  // A row links into the Inventory only when the head IS the loaded scan.
  const linkable = data !== null && data.head.id === current?.id;

  const counts = data
    ? [
        { name: "New", value: `+${data.new.length}`, sub: "New artefacts" },
        { name: "Resolved", value: `−${data.resolved.length}`, sub: "Resolved findings" },
        { name: "Changed", value: `${data.changed.length}`, sub: "Changed verdict or evidence" },
        {
          name: "Drift introduced",
          value: `${data.drift_introduced.length}`,
          sub: `New disagreement · ${data.drift_resolved.length} resolved`,
        },
      ]
    : [];

  return (
    <div>
      <ScreenHeader
        title="Compare Scans"
        subtitle="Diff a baseline against another stored scan, joined on the content-addressed bom-ref. A moved line is changed evidence; an artefact seen in a new place reports as resolved + new."
        actions={
          <>
            <ScanPicker label="Base" value={baseId} scans={scans} onChange={setBaseId} />
            <span className="font-mono text-[11px] uppercase text-ink-faint">vs</span>
            <ScanPicker label="Head" value={headId} scans={scans} onChange={setHeadId} />
          </>
        }
      />

      <div className="space-y-4 px-6 pb-6">
        {!ready ? (
          <EmptyPanel testId="compare-empty" title="Select two scans to compare">
            {current && !initial.base
              ? `Scan ${current.id.slice(0, 8)} has no parent row and no earlier scan of the same system, so there is no default baseline. `
              : ""}
            Pick a base and a different head above. The diff is computed by the server from the two
            stored documents; the console never guesses one.
          </EmptyPanel>
        ) : result.loading ? (
          <SkeletonBlock className="h-40 w-full" />
        ) : result.error ? (
          <EmptyPanel title="The comparison could not be loaded">{result.error}</EmptyPanel>
        ) : data ? (
          <>
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              {counts.map((count) => (
                <div key={count.name} data-testid="compare-count" className="rounded-lg border border-line bg-panel p-5">
                  <div className="eyebrow">{count.name}</div>
                  <div className="mt-3 text-[30px] font-light leading-none tabular-nums text-ink">{count.value}</div>
                  <div className="mt-2 text-[12px] text-ink-faint">{count.sub}</div>
                </div>
              ))}
            </div>

            <Panel
              eyebrow={`Scan diff / ${rows.length} finding${rows.length === 1 ? "" : "s"} · ${data.unchanged} unchanged`}
              title="Changed evidence"
              meta={
                <Button
                  onClick={() =>
                    downloadText(
                      `ecdat-compare-${data.base.id.slice(0, 8)}-${data.head.id.slice(0, 8)}.json`,
                      `${JSON.stringify(data, null, 2)}\n`,
                      "application/json",
                    )
                  }
                >
                  <Download className="h-3.5 w-3.5" aria-hidden /> Export diff
                </Button>
              }
              bodyClassName="pt-1"
            >
              {rows.length === 0 ? (
                <EmptyPanel title="No differences">
                  {data.unchanged} artefact{data.unchanged === 1 ? "" : "s"} unchanged between the two scans.
                </EmptyPanel>
              ) : (
                <ul>
                  {rows.map((row) => (
                    <li
                      key={row.key}
                      title={row.detail || undefined}
                      className="grid grid-cols-[minmax(8rem,1fr)_minmax(0,2.2fr)_auto_1rem] items-center gap-4 border-t border-line py-3 first:border-t-0"
                    >
                      <span className="truncate font-mono text-[13px] text-ink">{row.name}</span>
                      <span className="min-w-0">
                        <span className="block text-[12px] text-ink-faint">{row.what}</span>
                        <span className="block truncate font-mono text-[12px] text-ink">{row.value}</span>
                      </span>
                      <Tag variant={row.tag === "Resolved" ? "plain" : "strong"}>{row.tag}</Tag>
                      {row.ref && linkable ? (
                        <a
                          href={hrefFor("inventory", { ref: row.ref })}
                          aria-label={`Open ${row.name} in the Inventory`}
                          className="text-ink-faint hover:text-ink"
                        >
                          <ChevronRight className="h-4 w-4" aria-hidden />
                        </a>
                      ) : (
                        <span />
                      )}
                    </li>
                  ))}
                </ul>
              )}
              <p className="mt-3 text-[11px] text-ink-faint">
                Base {data.base.id.slice(0, 8)} ({data.base.kind}) → head {data.head.id.slice(0, 8)} ({data.head.kind}).
              </p>
            </Panel>
          </>
        ) : null}
      </div>
    </div>
  );
}
