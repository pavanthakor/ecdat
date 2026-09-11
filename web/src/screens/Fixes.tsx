/**
 * VERIFIED FIXES -- rebuilt on the v2 mockup (fixes.html; ADR-0039): one fix
 * card per proposal from `GET /scans/{id}/fixes` -- current and target, the
 * verified diff, the lifecycle, and Copy patch / View finding / Re-scan.
 *
 * A fix is proposed on a SANDBOX COPY and verified by re-scanning it (ADR-0015);
 * nothing here touches the target. The API carries a diff ONLY for a verified
 * fix, and this screen keeps that invariant visible: an unverified fix shows
 * its reason and no patch to copy.
 *
 * The mockup's lifecycle is kept, with only what ECDAT KNOWS marked done: a
 * fix is proposed, and it passed its sandbox verification or it did not.
 * Whether the patch was applied to the real target, and whether a later scan
 * came back clean, is not tracked -- so those steps are never drawn as done.
 * "Target" is the pack's migration label (ADR-0030), or says there is none;
 * the card's band is the artefact's, from the loaded document.
 *
 * Since ADR-0035 a fix pass and a re-scan are JOBS: the screen queues one and
 * follows it. And the patches are served to an ADMIN key only, so a viewer is
 * told that plainly rather than shown a 403.
 */
import { Copy, FileSearch, RefreshCw } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import { getFixes, runFix, waitForJob } from "@/api/client";
import type { Artefact, FixEntry, JobStatus, ScanSummary } from "@/api/types";
import { DiffBlock } from "@/components/ArtefactDrawer";
import { ScreenHeader } from "@/components/Panel";
import { BandTag, EmptyState, Notice, Prov } from "@/components/v2";
import { cn, formatDateTime, shortLocator, shortRef } from "@/lib/format";
import { hrefFor } from "@/lib/router";
import { canAdmin, NEEDS_ADMIN, useAuth } from "@/state/auth";
import { diffStats, fipsTag, targetOf } from "@/state/metrics";
import { useRemote } from "@/state/remote";
import { useRescan } from "@/state/rescan";

/** What the artefact is today, with its key size when the name does not carry it. */
function currentOf(artefact: Artefact): string {
  const bits = artefact.params.key_size;
  return bits && !artefact.name.includes(bits) ? `${artefact.name}-${bits}` : artefact.name;
}

function placeOf(artefact: Artefact | undefined): string | null {
  if (!artefact) return null;
  return artefact.endpoint ?? (artefact.occurrences[0] ? shortLocator(artefact.occurrences[0].locator) : null);
}

/**
 * The mockup's four steps, each marked only as far as ECDAT knows it. The
 * first step not done is "current"; nothing after it is claimed.
 */
function Lifecycle({ verified }: { verified: boolean }) {
  const steps: { label: string; state: "done" | "current" | "failed" | "pending"; title: string }[] = [
    { label: "Proposed", state: "done", title: "A template applied to this finding" },
    verified
      ? { label: "Verified in sandbox", state: "done", title: "Re-scanning the sandbox copy no longer found it" }
      : { label: "Not verified in sandbox", state: "failed", title: "The sandbox re-scan still found it" },
    {
      label: "Applied externally",
      state: verified ? "current" : "pending",
      title: "Not tracked: ECDAT never modifies the target, so applying the patch is yours",
    },
    { label: "Re-scanned", state: "pending", title: "Re-scan the target after applying it, then compare the two scans" },
  ];
  return (
    <div className="lifecycle" data-testid="lifecycle">
      {steps.map((step, index) => (
        <div key={step.label} className="contents">
          {index > 0 ? <div className="lc-line" /> : null}
          <div className={cn("lc-step", step.state)} data-state={step.state} title={step.title}>
            <span className="lc-dot" />
            {step.label}
          </div>
        </div>
      ))}
    </div>
  );
}

function FixCard({
  fix,
  artefact,
  onRescan,
  rescanning,
}: {
  fix: FixEntry;
  artefact: Artefact | undefined;
  onRescan: () => void;
  rescanning: boolean;
}) {
  const [copied, setCopied] = useState<"idle" | "copied" | "failed">("idle");
  const patch = fix.verified ? fix.diff : null;
  const stats = patch ? diffStats(patch) : null;
  const fips = fipsTag(fix.source);
  const target = artefact ? targetOf(artefact) : null;
  const place = placeOf(artefact);

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
      className={cn("fix-card in", !fix.verified && "unverified")}
    >
      <div className="fix-head">
        <div className="min-w-0">
          <div className="fix-title">{fix.component}</div>
          <div className="panel-sub truncate">
            {place ? `${place} · ` : ""}template {fix.template} · bom-ref {shortRef(fix.bom_ref)}
          </div>
        </div>
        <div className="flex flex-wrap items-center justify-end gap-1.5">
          {fips ? (
            <span className="format-tag" title={fix.source ?? undefined}>
              {fips}
            </span>
          ) : null}
          {stats ? (
            <span className="format-tag" title="Size of the verified patch">
              +{stats.added} −{stats.removed} · {stats.files} file{stats.files === 1 ? "" : "s"}
            </span>
          ) : null}
          <Prov kind={fix.verified ? "verified" : "provisional"}>{fix.verified ? "Verified" : "Not verified"}</Prov>
          {artefact ? <BandTag band={artefact.band} /> : null}
        </div>
      </div>

      <div className="fix-swap">
        <div className="fix-col">
          <div className="fix-col-label">Current</div>
          <div className="fix-col-value">{artefact ? currentOf(artefact) : fix.component}</div>
        </div>
        <div className="fix-col">
          <div className="fix-col-label">Target</div>
          {target ? (
            <div className="fix-col-value" title="The pack's migration label (ADR-0030): a family, not a parameter set">
              {target}
            </div>
          ) : (
            <div className="fix-col-value absent">no target labelled by a pack</div>
          )}
        </div>
      </div>

      {patch ? (
        <DiffBlock diff={patch} note={fix.reason} />
      ) : (
        <div className="empty-inline">
          <p className="empty-title">No patch to copy</p>
          <p className="empty-text">{fix.reason}</p>
        </div>
      )}
      {fix.source ? <p className="diff-note">Source: {fix.source}</p> : null}

      <Lifecycle verified={fix.verified} />

      <div className="fix-actions">
        {patch ? (
          <button type="button" className="btn-primary" onClick={copy}>
            <Copy className="h-3.5 w-3.5" aria-hidden />
            {copied === "copied" ? "Copied" : copied === "failed" ? "Copy failed — select the diff" : "Copy patch"}
          </button>
        ) : null}
        <a className="btn-ghost" href={hrefFor("inventory", { ref: fix.bom_ref })}>
          <FileSearch className="h-3.5 w-3.5" aria-hidden /> View finding
        </a>
        <button
          type="button"
          className="btn-ghost"
          onClick={onRescan}
          disabled={rescanning}
          title="Scan the same target again, e.g. after applying the patch"
        >
          <RefreshCw className="h-3.5 w-3.5" aria-hidden /> {rescanning ? "Re-scanning…" : "Re-scan"}
        </button>
      </div>
    </article>
  );
}

type Pass = { state: "idle" } | { state: "running"; job?: string; status?: JobStatus } | { state: "error"; message: string };

export function FixesScreen({ scan, artefacts = [] }: { scan: ScanSummary | null; artefacts?: Artefact[] }) {
  const { principal } = useAuth();
  const admin = canAdmin(principal);
  const fixes = useRemote(scan && admin ? `fixes:${scan.id}` : null, () => getFixes((scan as ScanSummary).id));
  const [pass, setPass] = useState<Pass>({ state: "idle" });
  const { rescan, start: rescanTarget } = useRescan(scan);
  const byRef = useMemo(() => new Map(artefacts.map((a) => [a.bomRef, a])), [artefacts]);
  // The fix pass this screen follows; leaving the screen stops the following.
  const following = useRef(new Set<AbortController>());
  useEffect(() => {
    const controllers = following.current;
    return () => controllers.forEach((controller) => controller.abort());
  }, []);

  async function runPass() {
    if (!scan) return;
    const controller = new AbortController();
    following.current.add(controller);
    const { signal } = controller;
    setPass({ state: "running" });
    try {
      const accepted = await runFix(scan.id);
      setPass({ state: "running", job: accepted.job_id, status: accepted.status });
      await waitForJob(accepted.job_id, {
        signal,
        onUpdate: (job) => setPass({ state: "running", job: job.id, status: job.status }),
      });
      setPass({ state: "idle" });
      fixes.reload();
    } catch (cause) {
      if (signal.aborted) return;
      setPass({ state: "error", message: cause instanceof Error ? cause.message : String(cause) });
    }
  }

  const running = pass.state === "running";
  const runLabel =
    pass.state === "running" && pass.job
      ? `Fix pass job ${pass.job.slice(0, 8)} is ${pass.status ?? "queued"}. It re-scans each finding twice; this page follows it.`
      : null;
  const data = fixes.data;
  const verified = data?.fixes.filter((f) => f.verified).length ?? 0;

  let body: React.ReactNode;
  if (!scan) {
    body = <EmptyState title="No scan selected" />;
  } else if (!admin) {
    body = (
      <EmptyState title="Verified fixes need an admin key">
        A verified patch is a working change to an estate's weakest cryptography, so the API serves fix results
        to an admin key only (ADR-0035). This key is a viewer. The Inventory still shows every finding with its
        recommended action.
      </EmptyState>
    );
  } else if (fixes.loading) {
    body = (
      <>
        <div className="fix-card h-56 animate-pulse" />
        <div className="fix-card h-56 animate-pulse" />
      </>
    );
  } else if (fixes.error) {
    body = (
      <EmptyState title="Fix results could not be loaded">
        {fixes.error}. This is a failed request, not an empty queue.
      </EmptyState>
    );
  } else if (!data || data.fix_scan_id === null) {
    body = (
      <EmptyState
        title="No fix pass has been run for this scan"
        action={
          <button type="button" className="btn-primary" onClick={runPass} disabled={running}>
            {running ? "Running fix pass…" : "Run fix pass"}
          </button>
        }
      >
        A fix pass copies the target to a sandbox, applies each applicable template, and re-scans the copy to
        verify the finding is gone. It is slow — two re-scans per finding — so it runs as a job on the server,
        and it never modifies the target itself.
      </EmptyState>
    );
  } else if (data.fixes.length === 0) {
    body = (
      <EmptyState title="The fix pass found nothing it could fix">
        No template applied to any finding in this scan. Findings without a template are listed in the Inventory
        with their recommended action.
      </EmptyState>
    );
  } else {
    body = (
      <>
        <p className="page-sub mb-3" data-testid="fix-pass-line">
          Fix pass {data.fix_scan_id.slice(0, 8)} · {formatDateTime(data.created_at)} · {verified} verified ·{" "}
          {data.fixes.length - verified} not verified — each applied to a sandbox copy and re-scanned there.
        </p>
        {data.fixes.map((fix) => (
          <FixCard
            key={`${fix.template}:${fix.bom_ref}`}
            fix={fix}
            artefact={byRef.get(fix.bom_ref)}
            onRescan={() => void rescanTarget()}
            rescanning={rescan.state === "running"}
          />
        ))}
      </>
    );
  }

  return (
    <div className="content">
      <ScreenHeader
        title="Verified Fixes"
        subtitle="Proposed remediation, ready to review, apply, and confirm with a re-scan. Each patch was verified on a sandbox copy; nothing here touches your code."
        actions={
          admin && data?.fix_scan_id ? (
            <button type="button" className="btn-ghost" onClick={runPass} disabled={running}>
              <RefreshCw className="h-3.5 w-3.5" aria-hidden /> {running ? "Running…" : "Re-run fix pass"}
            </button>
          ) : undefined
        }
      />
      {runLabel ? (
        <Notice mono testId="fix-job">
          {runLabel}
        </Notice>
      ) : null}
      {pass.state === "error" ? <Notice error>{pass.message}</Notice> : null}
      {rescan.message ? <Notice error={rescan.state === "error"}>{rescan.message}</Notice> : null}
      {!admin && scan ? <span className="sr-only">{NEEDS_ADMIN}</span> : null}
      {body}
    </div>
  );
}
