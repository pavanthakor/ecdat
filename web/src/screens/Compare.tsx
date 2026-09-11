/**
 * COMPARE SCANS -- what changed between two stored scans (ADR-0031), rebuilt
 * on the v2 mockup (compare.html; ADR-0039): the two scans face to face with a
 * picker in each, four count cards, then "Changed evidence" with a NEW /
 * CHANGED / RESOLVED tag per row.
 *
 * Read from `GET /scans/{base}/compare/{head}`, joined on the content-addressed
 * bom-ref; the console computes no diff of its own. The default pair comes from
 * the store's links, and with no such pair the screen asks for two scans
 * instead of inventing a baseline. Counts and tags are neutral ink and border:
 * the mockup paints NEW green, CHANGED amber and "drift introduced" red, and
 * colour here means a band (ADR-0031).
 */
import { ChevronRight, Download } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { compareScans } from "@/api/client";
import type { CompareChange, CompareResponse, ScanSummary } from "@/api/types";
import { ScreenHeader } from "@/components/Panel";
import { EmptyState, PanelHead } from "@/components/v2";
import { downloadText } from "@/lib/download";
import { cn, formatDate } from "@/lib/format";
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

const TAG_CLASS: Record<DiffRow["tag"], string> = {
  New: "tag-new",
  Changed: "tag-changed",
  Resolved: "tag-resolved",
};

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
      what: `New drift finding · ${drift.kind}`,
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

function ScanCard({
  label,
  short,
  value,
  scans,
  onChange,
}: {
  label: string;
  short: string;
  value: string;
  scans: ScanSummary[];
  onChange: (id: string) => void;
}) {
  const chosen = scans.find((scan) => scan.id === value) ?? null;
  return (
    <div className="compare-scan" data-testid={`compare-${short.toLowerCase()}`}>
      <div className="compare-scan-label">{label}</div>
      <div className="compare-scan-date">{chosen ? formatDate(chosen.created_at) : "—"}</div>
      <div className="compare-scan-id">
        {chosen ? `${chosen.id.slice(0, 8)} · ${chosen.kind} · ${chosen.target.ref}` : "no scan chosen"}
      </div>
      <select aria-label={`${short} scan`} value={value} onChange={(event) => onChange(event.target.value)}>
        <option value="">choose a scan</option>
        {scans.map((scan) => (
          <option key={scan.id} value={scan.id}>
            {scan.id.slice(0, 8)} · {formatDate(scan.created_at)}
            {scan.kind === "scan" ? "" : ` · ${scan.kind}`}
          </option>
        ))}
      </select>
    </div>
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
        { name: "New", value: `+${data.new.length}`, sub: "new artefacts" },
        { name: "Resolved", value: `−${data.resolved.length}`, sub: "no longer found" },
        { name: "Changed", value: `${data.changed.length}`, sub: "verdict or evidence" },
        {
          name: "Drift introduced",
          value: `${data.drift_introduced.length}`,
          sub: `${data.drift_resolved.length} resolved`,
        },
      ]
    : [];

  return (
    <div className="content">
      <ScreenHeader
        title="Compare Scans"
        subtitle="Diff a baseline against another stored scan, joined on the content-addressed bom-ref. A moved line is changed evidence; an artefact seen in a new place reports as resolved + new."
      />

      <section className="panel in mb-3" style={{ animationDelay: "0.04s" }}>
        <div className="compare-head">
          <ScanCard label="Scan A · base" short="Base" value={baseId} scans={scans} onChange={setBaseId} />
          <div className="compare-vs">VS</div>
          <ScanCard label="Scan B · head" short="Head" value={headId} scans={scans} onChange={setHeadId} />
        </div>
        {data ? (
          <div className="stat-row of4 !mb-0">
            {counts.map((count) => (
              <div key={count.name} data-testid="compare-count" className="stat-card">
                <div className="stat-top">
                  <div className="stat-label">{count.name}</div>
                </div>
                <div className="stat-bottom">
                  <div className="stat-num">{count.value}</div>
                  <div className="stat-delta">{count.sub}</div>
                </div>
              </div>
            ))}
          </div>
        ) : null}
      </section>

      {!ready ? (
        <EmptyState testId="compare-empty" title="Select two scans to compare">
          {current && !initial.base
            ? `Scan ${current.id.slice(0, 8)} has no parent row and no earlier scan of the same system, so there is no default baseline. `
            : ""}
          Pick a base and a different head above. The diff is computed by the server from the two stored documents;
          the console never guesses one.
        </EmptyState>
      ) : result.loading ? (
        <div className="panel h-40 animate-pulse" />
      ) : result.error ? (
        <EmptyState title="The comparison could not be loaded">{result.error}</EmptyState>
      ) : data ? (
        <section className="panel in" style={{ animationDelay: "0.1s" }}>
          <PanelHead
            title="Changed evidence"
            sub={`Every artefact whose state differs between scan A and scan B · ${rows.length} finding${rows.length === 1 ? "" : "s"} · ${data.unchanged} unchanged`}
            right={
              <button
                type="button"
                className="btn-ghost"
                onClick={() =>
                  downloadText(
                    `ecdat-compare-${data.base.id.slice(0, 8)}-${data.head.id.slice(0, 8)}.json`,
                    `${JSON.stringify(data, null, 2)}\n`,
                    "application/json",
                  )
                }
              >
                Export diff <Download className="h-3.5 w-3.5" aria-hidden />
              </button>
            }
          />
          {rows.length === 0 ? (
            <EmptyState title="No differences">
              {data.unchanged} artefact{data.unchanged === 1 ? "" : "s"} unchanged between the two scans.
            </EmptyState>
          ) : (
            <div className="mt-2">
              {rows.map((row) => (
                <div key={row.key} data-testid="change-row" data-tag={row.tag} title={row.detail || undefined} className="change-row">
                  <div className="change-artefact" title={row.name}>
                    {row.name}
                  </div>
                  <div className="change-detail">
                    {row.what}
                    <div className="change-endpoint" title={row.value}>
                      {row.value}
                    </div>
                  </div>
                  <div className={cn("change-tag", TAG_CLASS[row.tag])}>{row.tag}</div>
                  {row.ref && linkable ? (
                    <a
                      href={hrefFor("inventory", { ref: row.ref })}
                      aria-label={`Open ${row.name} in the Inventory`}
                      className="text-ink-faint hover:text-ink"
                    >
                      <ChevronRight className="h-4 w-4" aria-hidden />
                    </a>
                  ) : (
                    <span className="w-4" />
                  )}
                </div>
              ))}
            </div>
          )}
          <p className="page-sub mt-3">
            Base {data.base.id.slice(0, 8)} ({data.base.kind}) → head {data.head.id.slice(0, 8)} ({data.head.kind}).
          </p>
        </section>
      ) : null}
    </div>
  );
}
