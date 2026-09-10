/**
 * COMPARE SCANS -- what changed between two stored scans (ADR-0031).
 *
 * Read from `GET /scans/{base}/compare/{head}`, which joins on the content-
 * addressed bom-ref; the console computes no diff of its own. The default pair
 * comes from the store's links -- a derived row against its parent, a scan
 * against the previous scan of its system -- and with no such pair the screen
 * asks for two scans instead of inventing a baseline.
 */
import { ArrowLeftRight } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { compareScans } from "@/api/client";
import type { CompareChange, CompareDrift, CompareEntry, ScanSummary } from "@/api/types";
import { EmptyPanel } from "@/components/Honest";
import { Button, Panel, ScreenHeader, SkeletonBlock, Tag } from "@/components/Panel";
import { cn, formatDateTime, shortRef } from "@/lib/format";
import { hrefFor } from "@/lib/router";
import { defaultComparison } from "@/state/metrics";
import { useRemote } from "@/state/remote";

const select =
  "h-7 min-w-0 max-w-[22rem] border border-line bg-ground px-1.5 font-mono text-2xs text-ink-dim focus:border-ink-faint focus:outline-none";

function label(scan: ScanSummary): string {
  return `${scan.id.slice(0, 8)} · ${scan.kind} · ${scan.target.system ?? scan.target.ref} · ${formatDateTime(scan.created_at)}`;
}

function EntryList({ entries, empty }: { entries: CompareEntry[]; empty: string }) {
  if (entries.length === 0) return <p className="text-2xs text-ink-faint">{empty}</p>;
  return (
    <ul className="divide-y divide-line-soft">
      {entries.map((entry) => (
        <li key={entry.bom_ref} className="flex items-baseline gap-2 py-1">
          <span className="text-xs text-ink">{entry.name}</span>
          <span className="font-mono text-[10px] text-ink-faint">{shortRef(entry.bom_ref)}</span>
          <span className="ml-auto font-mono text-[10px] text-ink-dim">
            {entry.band ?? "—"} · {entry.score ?? "—"}
          </span>
        </li>
      ))}
    </ul>
  );
}

function ChangeList({ changes }: { changes: CompareChange[] }) {
  if (changes.length === 0) return <p className="text-2xs text-ink-faint">No artefact on both sides changed.</p>;
  return (
    <ul className="divide-y divide-line-soft">
      {changes.map((change) => (
        <li key={change.bom_ref} className="py-1.5">
          <div className="flex items-baseline gap-2">
            <a href={hrefFor("inventory", { ref: change.bom_ref })} className="text-xs text-ink hover:underline">
              {change.name}
            </a>
            <span className="font-mono text-[10px] text-ink-faint">{shortRef(change.bom_ref)}</span>
            <span className="ml-auto flex gap-1">
              {change.fields.map((field) => (
                <Tag key={field}>{field}</Tag>
              ))}
            </span>
          </div>
          <div className="mt-0.5 flex flex-wrap gap-x-4 font-mono text-[10px] text-ink-dim">
            {change.fields
              .filter((field) => field !== "evidence")
              .map((field) => {
                const key = field as keyof CompareChange["before"];
                return (
                  <span key={field}>
                    {field} {String(change.before[key] ?? "—")} → {String(change.after[key] ?? "—")}
                  </span>
                );
              })}
          </div>
          {change.evidence_added.length + change.evidence_removed.length > 0 ? (
            <ul className="mt-1 space-y-0.5 font-mono text-[10px]">
              {change.evidence_removed.map((entry) => (
                <li key={`-${entry}`} className="text-ink-faint">
                  − {entry}
                </li>
              ))}
              {change.evidence_added.map((entry) => (
                <li key={`+${entry}`} className="text-ink-dim">
                  + {entry}
                </li>
              ))}
            </ul>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

function DriftList({ drifts, empty }: { drifts: CompareDrift[]; empty: string }) {
  if (drifts.length === 0) return <p className="text-2xs text-ink-faint">{empty}</p>;
  return (
    <ul className="divide-y divide-line-soft">
      {drifts.map((drift) => (
        <li key={`${drift.bom_ref}:${drift.kind}:${drift.declared}`} className="py-1.5">
          <div className="flex items-baseline gap-2">
            <span className="text-xs text-ink">{drift.name}</span>
            <Tag>{drift.kind}</Tag>
          </div>
          <div className="mt-0.5 font-mono text-[10px] text-ink-dim">
            declared {drift.declared} · compared {drift.observed}
          </div>
          <p className="mt-0.5 text-[10px] text-ink-faint">{drift.cause}</p>
        </li>
      ))}
    </ul>
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

  const counts = data
    ? [
        ["New", data.new.length],
        ["Resolved", data.resolved.length],
        ["Changed", data.changed.length],
        ["Drift introduced", data.drift_introduced.length],
        ["Drift resolved", data.drift_resolved.length],
      ]
    : [];

  return (
    <div>
      <ScreenHeader
        title="Compare Scans"
        subtitle="New, resolved and changed artefacts between two stored scans, joined on the content-addressed bom-ref. A moved line is changed evidence; an artefact seen in a new place reports as resolved + new."
      />
      <div className="flex flex-wrap items-center gap-3 border-b border-line bg-panel px-5 py-2 text-2xs">
        <label className="flex items-center gap-2">
          <span className="text-[10px] uppercase tracking-wider text-ink-faint">Base</span>
          <select aria-label="Base scan" className={select} value={baseId} onChange={(e) => setBaseId(e.target.value)}>
            <option value="">choose a scan</option>
            {scans.map((scan) => (
              <option key={scan.id} value={scan.id}>
                {label(scan)}
              </option>
            ))}
          </select>
        </label>
        <Button
          variant="quiet"
          aria-label="Swap base and head"
          onClick={() => {
            setBaseId(headId);
            setHeadId(baseId);
          }}
        >
          <ArrowLeftRight className="h-3 w-3" aria-hidden />
        </Button>
        <label className="flex items-center gap-2">
          <span className="text-[10px] uppercase tracking-wider text-ink-faint">Head</span>
          <select aria-label="Head scan" className={select} value={headId} onChange={(e) => setHeadId(e.target.value)}>
            <option value="">choose a scan</option>
            {scans.map((scan) => (
              <option key={scan.id} value={scan.id}>
                {label(scan)}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="space-y-3 p-4">
        {!ready ? (
          <EmptyPanel testId="compare-empty" title="Select two scans to compare">
            {current && !initial.base
              ? `Scan ${current.id.slice(0, 8)} has no parent row and no earlier scan of the same system, so there is no default baseline. `
              : ""}
            Pick a base and a different head above. The diff is computed by the server from
            the two stored documents; the console never guesses one.
          </EmptyPanel>
        ) : result.loading ? (
          <SkeletonBlock className="h-32 w-full" />
        ) : result.error ? (
          <EmptyPanel title="The comparison could not be loaded">{result.error}</EmptyPanel>
        ) : data ? (
          <>
            <div className="grid grid-cols-2 gap-px border border-line bg-line sm:grid-cols-6">
              {counts.map(([name, value]) => (
                <div key={name} data-testid="compare-count" className="bg-panel px-3 py-2">
                  <div className="eyebrow">{name}</div>
                  <div className="font-mono text-xl tabular-nums text-ink">{value}</div>
                </div>
              ))}
              <div className="bg-panel px-3 py-2">
                <div className="eyebrow">Unchanged</div>
                <div className="font-mono text-xl tabular-nums text-ink-faint">{data.unchanged}</div>
              </div>
            </div>
            <div className="grid gap-3 lg:grid-cols-2">
              <Panel title={`New (${data.new.length})`}>
                <EntryList entries={data.new} empty="Nothing appeared." />
              </Panel>
              <Panel title={`Resolved (${data.resolved.length})`}>
                <EntryList entries={data.resolved} empty="Nothing disappeared." />
              </Panel>
            </div>
            <Panel title={`Changed · verdicts and evidence (${data.changed.length})`}>
              <ChangeList changes={data.changed} />
            </Panel>
            <div className="grid gap-3 lg:grid-cols-2">
              <Panel title={`Drift introduced (${data.drift_introduced.length})`}>
                <DriftList drifts={data.drift_introduced} empty="No new disagreement between views." />
              </Panel>
              <Panel title={`Drift resolved (${data.drift_resolved.length})`}>
                <DriftList drifts={data.drift_resolved} empty="No disagreement went away." />
              </Panel>
            </div>
            <p className={cn("text-[10px] text-ink-faint")}>
              Base {data.base.id.slice(0, 8)} ({data.base.kind}) → head {data.head.id.slice(0, 8)} ({data.head.kind}).
            </p>
          </>
        ) : null}
      </div>
    </div>
  );
}
