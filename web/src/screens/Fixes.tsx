/**
 * VERIFIED FIXES -- the remediation queue from `GET /scans/{id}/fixes`, laid
 * out as web/design/ has it (ADR-0032): one "remediation queue" card holding a
 * card per fix -- name, FIPS and size tags, a `current -> fix` line, the diff,
 * and Copy Patch / View Finding / Re-scan.
 *
 * A fix is proposed on a SANDBOX COPY and verified by re-scanning it (ADR-0015);
 * nothing here touches the target. The API carries a diff ONLY for a verified
 * fix, and this screen keeps that invariant visible: an unverified fix shows
 * its reason and no patch to copy.
 */
import { ArrowRight, Copy, FileSearch, RefreshCw } from "lucide-react";
import { useState } from "react";

import { createScan, getFixes, runFix } from "@/api/client";
import type { Exposure, FixEntry, ScanSummary, Sector, TargetKind } from "@/api/types";
import { DiffBlock } from "@/components/ArtefactDrawer";
import { EmptyPanel } from "@/components/Honest";
import { Button, LinkButton, Panel, ScreenHeader, SkeletonBlock, Tag } from "@/components/Panel";
import { cn, formatDateTime, pad2 } from "@/lib/format";
import { hrefFor } from "@/lib/router";
import { Z_DEFAULT } from "@/state/inventory";
import { diffStats, fipsTag } from "@/state/metrics";
import { useRemote } from "@/state/remote";

function FixCard({ fix, onRescan, rescanning }: { fix: FixEntry; onRescan: () => void; rescanning: boolean }) {
  const [copied, setCopied] = useState<"idle" | "copied" | "failed">("idle");
  const patch = fix.verified ? fix.diff : null;
  const stats = patch ? diffStats(patch) : null;
  const fips = fipsTag(fix.source);

  async function copy() {
    if (!patch) return;
    try {
      await navigator.clipboard.writeText(patch);
      setCopied("copied");
    } catch {
      setCopied("failed");
    }
  }

  return (
    <article
      data-testid="fix-card"
      data-verified={String(fix.verified)}
      className={cn(
        "rounded-lg p-4",
        fix.verified ? "border border-line bg-raised/30" : "border border-dashed border-ink-faint/60",
      )}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-[14px] font-semibold text-ink">{fix.component}</div>
          <div className="mt-1.5 flex items-center gap-2 font-mono text-[12px]">
            <span className="text-ink-faint">current</span>
            <ArrowRight className="h-3 w-3 text-ink-faint" aria-hidden />
            <span className="text-ink">{fix.template}</span>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {fips ? <Tag title={fix.source ?? undefined}>{fips}</Tag> : null}
          {stats ? (
            <Tag title="Size of the verified patch">
              +{stats.added} −{stats.removed} · {stats.files} file{stats.files === 1 ? "" : "s"}
            </Tag>
          ) : null}
          <Tag variant={fix.verified ? "verified" : "provisional"}>{fix.verified ? "Verified" : "Not verified"}</Tag>
        </div>
      </div>
      <p className="mt-2 text-[12px] leading-relaxed text-ink-dim">{fix.reason}</p>
      {fix.source ? <p className="mt-1 text-[11px] text-ink-faint">Source: {fix.source}</p> : null}
      {patch ? <DiffBlock diff={patch} /> : null}
      <div className="mt-3 flex flex-wrap items-center gap-2">
        {patch ? (
          <Button onClick={copy}>
            <Copy className="h-3.5 w-3.5" aria-hidden />
            {copied === "copied" ? "Copied" : copied === "failed" ? "Copy failed — select the diff" : "Copy patch"}
          </Button>
        ) : null}
        <LinkButton variant="quiet" href={hrefFor("inventory", { ref: fix.bom_ref })}>
          <FileSearch className="h-3.5 w-3.5" aria-hidden /> View finding
        </LinkButton>
        <Button
          variant="quiet"
          onClick={onRescan}
          disabled={rescanning}
          title="Scan the same target again, e.g. after applying the patch"
        >
          <RefreshCw className="h-3.5 w-3.5" aria-hidden /> {rescanning ? "Re-scanning…" : "Re-scan"}
        </Button>
      </div>
    </article>
  );
}

export function FixesScreen({ scan }: { scan: ScanSummary | null }) {
  const fixes = useRemote(scan ? `fixes:${scan.id}` : null, () => getFixes((scan as ScanSummary).id));
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [rescan, setRescan] = useState<{ state: "idle" | "running" | "done" | "error"; message?: string }>({
    state: "idle",
  });

  async function runPass() {
    if (!scan) return;
    setRunning(true);
    setRunError(null);
    try {
      await runFix(scan.id);
      fixes.reload();
    } catch (cause) {
      setRunError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setRunning(false);
    }
  }

  async function rescanTarget() {
    if (!scan) return;
    setRescan({ state: "running" });
    try {
      const created = await createScan({
        kind: scan.target.kind as TargetKind,
        ref: scan.target.ref,
        system: scan.target.system,
        data_class: scan.target.data_class,
        sector: (scan.sector ?? "other") as Sector,
        exposure: (scan.exposure ?? "unknown") as Exposure,
        z_years: scan.z_years ?? Z_DEFAULT,
      });
      setRescan({
        state: "done",
        message: `Stored as scan ${created.scan_id.slice(0, 8)} — select it in Scans, then compare.`,
      });
    } catch (cause) {
      setRescan({ state: "error", message: cause instanceof Error ? cause.message : String(cause) });
    }
  }

  const data = fixes.data;
  const verified = data?.fixes.filter((f) => f.verified).length ?? 0;

  let body: React.ReactNode;
  if (!scan) {
    body = <EmptyPanel title="No scan selected" />;
  } else if (fixes.loading) {
    body = <SkeletonBlock className="h-40 w-full" />;
  } else if (fixes.error) {
    body = (
      <EmptyPanel title="Fix results could not be loaded">
        {fixes.error}. This is a failed request, not an empty queue.
      </EmptyPanel>
    );
  } else if (!data || data.fix_scan_id === null) {
    body = (
      <EmptyPanel title="No fix pass has been run for this scan">
        A fix pass copies the target to a sandbox, applies each applicable template, and re-scans
        the copy to verify the finding is gone. It is slow — two re-scans per finding — and it
        never modifies the target itself.
        <div className="mt-3">
          <Button variant="primary" onClick={runPass} disabled={running}>
            {running ? "Running fix pass…" : "Run fix pass"}
          </Button>
        </div>
      </EmptyPanel>
    );
  } else if (data.fixes.length === 0) {
    body = (
      <EmptyPanel title="The fix pass found nothing it could fix">
        No template applied to any finding in this scan. Findings without a template are listed in
        the Inventory with their recommended action.
      </EmptyPanel>
    );
  } else {
    body = (
      <Panel
        eyebrow={`Remediation queue / ${pad2(data.fixes.length)} proposals`}
        title="Evidence-backed migrations"
        meta={
          <>
            <Tag variant="verified">{verified} verified</Tag>
            {data.fixes.length - verified > 0 ? (
              <Tag variant="provisional">{data.fixes.length - verified} not verified</Tag>
            ) : null}
          </>
        }
      >
        <p className="-mt-2 mb-4 font-mono text-[10.5px] uppercase tracking-wider text-ink-faint">
          fix pass {data.fix_scan_id.slice(0, 8)} · {formatDateTime(data.created_at)}
        </p>
        <div className="space-y-3">
          {data.fixes.map((fix) => (
            <FixCard
              key={`${fix.template}:${fix.bom_ref}`}
              fix={fix}
              onRescan={rescanTarget}
              rescanning={rescan.state === "running"}
            />
          ))}
        </div>
      </Panel>
    );
  }

  return (
    <div>
      <ScreenHeader
        title="Verified Fixes"
        subtitle="Review evidence-backed migration patches before re-scan. Each was applied to a sandbox copy and verified by re-scanning it; nothing here touches your code, and a patch is shown only when its verification passed."
        actions={
          data?.fix_scan_id ? (
            <Button onClick={runPass} disabled={running}>
              <RefreshCw className="h-3.5 w-3.5" aria-hidden /> {running ? "Running…" : "Re-run fix pass"}
            </Button>
          ) : undefined
        }
      />
      <div className="space-y-3 px-6 pb-6">
        {runError ? (
          <p className="rounded-md border border-critical/40 bg-critical/10 px-3 py-2 text-[12px] text-critical">{runError}</p>
        ) : null}
        {rescan.message ? (
          <p
            className={cn(
              "rounded-md border px-3 py-2 text-[12px]",
              rescan.state === "error" ? "border-critical/40 bg-critical/10 text-critical" : "border-line text-ink-dim",
            )}
          >
            {rescan.message}
          </p>
        ) : null}
        {body}
      </div>
    </div>
  );
}
