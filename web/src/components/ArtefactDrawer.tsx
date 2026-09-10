/**
 * The drill-down: everything ECDAT knows about one artefact, and how it knows.
 *
 * The section order is the argument a reviewer actually makes: WHAT was found,
 * HOW SURE the scanner was (ADR-0034 -- a candidate is shown, and marked, never
 * presented as a confident finding), WHERE it was seen (evidence first -- a
 * claim without receipts is not a claim), WHY it scored what it did, whether
 * the views DISAGREE, and what to do about it. Provenance rides on the score
 * section, because that is where a reader is deciding whether to believe a
 * number.
 *
 * The fix comes from the artefact itself on a `kind: "fix"` row, or from
 * `GET /scans/{id}/fixes` otherwise. "Not loaded", "failed to load" and "no
 * fix proposed" are three different sentences here, never one.
 */
import type { Artefact, FixEntry } from "@/api/types";
import { BAND_STYLE, cn } from "@/lib/format";
import { hrefFor } from "@/lib/router";
import { targetOf } from "@/state/metrics";
import { CertaintyBadge, ConfidenceBlock, FactList, ProvenanceBadge } from "./Provenance";
import { Sheet, SheetContent } from "./ui/sheet";

export type FixLookup =
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "loaded"; entry: FixEntry | null };

interface Props {
  artefact: Artefact | null;
  onClose: () => void;
  fixLookup?: FixLookup;
}

function Section({
  title,
  count,
  children,
}: {
  title: string;
  count?: number;
  children: React.ReactNode;
}) {
  return (
    <section className="mb-5">
      <h4 className="mb-2 flex items-center justify-between text-2xs font-semibold uppercase tracking-widest text-ink-faint">
        <span>{title}</span>
        {count !== undefined ? (
          <span className="font-mono normal-case tracking-normal">{count}</span>
        ) : null}
      </h4>
      {children}
    </section>
  );
}

/**
 * A rendered unified diff, as the design has it: removed lines red, added lines
 * full-contrast, context faint. The red is git's convention, not a band.
 */
export function DiffBlock({ diff }: { diff: string }) {
  return (
    <pre className="mt-3 overflow-x-auto rounded-md border border-line bg-ground p-3 font-mono text-[11.5px] leading-relaxed">
      {diff.split("\n").map((line, index) => (
        <div
          key={index}
          className={
            line.startsWith("+++") || line.startsWith("---")
              ? "text-ink-dim"
              : line.startsWith("+")
                ? "text-ink"
                : line.startsWith("-")
                  ? "text-critical"
                  : "text-ink-faint"
          }
        >
          {line || " "}
        </div>
      ))}
    </pre>
  );
}

function FixBlock({ fix }: { fix: NonNullable<Artefact["fix"]> }) {
  return (
    <div
      className={cn(
        "border px-2.5 py-2",
        fix.verified ? "border-line bg-raised" : "border-dashed border-ink-faint/60",
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono text-2xs text-ink">{fix.template}</span>
        <span
          className={cn(
            "text-2xs uppercase tracking-wide",
            fix.verified ? "text-ink-dim" : "text-ink-faint",
          )}
        >
          {fix.verified ? "verified" : "not verified"}
        </span>
      </div>
      <p className="mt-1 text-2xs leading-relaxed text-ink-faint">{fix.reason}</p>
      {fix.verified && fix.diff ? <DiffBlock diff={fix.diff} /> : null}
    </div>
  );
}

function configurableText(value: boolean | null): string {
  if (value === null) return "not assessed";
  return value ? "yes — by configuration" : "no — fixed in code";
}

export function ArtefactDrawer({ artefact, onClose, fixLookup }: Props) {
  if (!artefact) return null;
  const style = BAND_STYLE[artefact.band];
  const lookedUp = fixLookup?.status === "loaded" ? fixLookup.entry : null;
  const fix = artefact.fix ?? (lookedUp ? { ...lookedUp } : null);

  return (
    <Sheet open onOpenChange={(open) => !open && onClose()}>
      <SheetContent title={artefact.name} description={artefact.bomRef}>
        <div className="mb-5 flex flex-wrap items-center gap-2">
          <span
            data-testid="band-chip"
            className={cn("flex items-baseline gap-2 border px-2.5 py-1", style.bg)}
          >
            <span className={cn("font-mono text-lg tabular-nums", style.text)}>
              {artefact.score}
            </span>
            <span className={cn("text-2xs uppercase tracking-wide", style.text)}>
              {artefact.band}
            </span>
          </span>
          <ProvenanceBadge artefact={artefact} />
          <CertaintyBadge artefact={artefact} />
          {artefact.quantumStatus ? (
            <span className="border border-line bg-raised px-2 py-0.5 text-2xs uppercase tracking-wide text-ink-dim">
              quantum: {artefact.quantumStatus}
            </span>
          ) : null}
        </div>

        <div className="mb-5 grid grid-cols-2 gap-px border border-line bg-line text-xs sm:grid-cols-3">
          {[
            ["views", artefact.views.join(", ")],
            ["asset type", artefact.assetType],
            ["usage", artefact.usage],
            ["primitive", artefact.primitive ?? "—"],
            ["endpoint", artefact.endpoint ?? "—"],
            ["coverage", artefact.coverageViews.join(", ") || "—"],
            ["configurable", configurableText(artefact.configurable)],
            ["pqc target", targetOf(artefact) ?? "no target labelled"],
            ["deadline", artefact.deadline ?? "none"],
          ].map(([label, value]) => (
            <div key={label} className="bg-panel px-2.5 py-1.5">
              <div className="text-2xs uppercase tracking-wide text-ink-faint">{label}</div>
              <div className="truncate font-mono text-ink-dim" title={value}>
                {value}
              </div>
            </div>
          ))}
        </div>

        <Section title="Confidence">
          <ConfidenceBlock artefact={artefact} />
        </Section>

        <Section title="Evidence" count={artefact.occurrences.length}>
          <ul className="space-y-1.5">
            {artefact.occurrences.map((occurrence, index) => (
              <li
                key={`${occurrence.locator}-${index}`}
                className="border border-line bg-panel px-2.5 py-2"
              >
                <div className="flex items-center gap-2">
                  <span className="truncate font-mono text-2xs text-ink">
                    {occurrence.locator}
                  </span>
                  <span className="ml-auto shrink-0 border border-line px-1 text-[9px] uppercase tracking-wide text-ink-faint">
                    {occurrence.scanner || occurrence.view}
                  </span>
                </div>
                <div className="mt-1 font-mono text-2xs text-ink-faint">{occurrence.detail}</div>
                {occurrence.snippet ? (
                  <pre className="mt-1.5 overflow-x-auto border-l-2 border-line-soft bg-ground px-2 py-1 font-mono text-2xs text-ink-dim">
                    {occurrence.snippet}
                  </pre>
                ) : null}
              </li>
            ))}
          </ul>
        </Section>

        {artefact.drift.length > 0 ? (
          <Section title="Drift" count={artefact.drift.length}>
            <ul className="space-y-1.5">
              {artefact.drift.map((drift, index) => (
                <li
                  key={`${drift.kind}-${index}`}
                  className="border-2 border-line bg-raised px-2.5 py-2"
                >
                  <span className="font-mono text-2xs text-ink">{drift.kind}</span>
                  <div className="mt-1.5 grid grid-cols-2 gap-2 text-2xs">
                    <div>
                      <span className="text-ink-faint">declared </span>
                      <span className="font-mono text-ink">{drift.declared}</span>
                    </div>
                    <div>
                      <span className="text-ink-faint">compared </span>
                      <span className="font-mono text-ink">{drift.observed}</span>
                    </div>
                  </div>
                  <p className="mt-1.5 text-2xs leading-relaxed text-ink-dim">{drift.cause}</p>
                  {drift.evidence.length > 0 ? (
                    <ul className="mt-1.5 space-y-0.5">
                      {drift.evidence.map((entry) => (
                        <li key={entry} className="font-mono text-2xs text-ink-faint">
                          {entry}
                        </li>
                      ))}
                    </ul>
                  ) : null}
                </li>
              ))}
            </ul>
          </Section>
        ) : null}

        <Section title="Why this score">
          <FactList artefact={artefact} />
        </Section>

        <Section title="Mosca terms">
          <div className="grid grid-cols-3 gap-px border border-line bg-line text-xs">
            {[
              ["x — data lifetime", artefact.xYears, artefact.bases.x],
              ["y — migration", artefact.yYears, artefact.bases.y],
              ["z — CRQC horizon", artefact.zYears, artefact.bases.z],
            ].map(([label, value, basis]) => (
              <div
                key={label as string}
                className="bg-panel px-2.5 py-2"
                title={(basis as string) ?? undefined}
              >
                <div className="text-2xs uppercase tracking-wide text-ink-faint">
                  {label as string}
                </div>
                <div className="font-mono text-base tabular-nums text-ink">
                  {value === null ? "—" : `${value}y`}
                </div>
              </div>
            ))}
          </div>
          <p className="mt-1.5 text-2xs leading-relaxed text-ink-faint">
            y and z are ESTIMATES, not measurements — hover each for its basis.
          </p>
        </Section>

        {artefact.labels.length > 0 ? (
          <Section title="Labels" count={artefact.labels.length}>
            <div className="flex flex-wrap gap-1">
              {artefact.labels.map((label) => {
                const provisional = label.includes("provisional");
                return (
                  <span
                    key={label}
                    className={cn(
                      "px-1.5 py-0.5 text-2xs",
                      provisional
                        ? "border border-dashed border-ink-faint/60 text-ink-faint"
                        : "border border-line bg-panel text-ink-dim",
                    )}
                  >
                    {label}
                  </span>
                );
              })}
            </div>
          </Section>
        ) : null}

        {artefact.actions.length > 0 ? (
          <Section title="Recommended action" count={artefact.actions.length}>
            <ul className="space-y-1.5">
              {artefact.actions.map((action) => {
                const provisional = action.startsWith("PROVISIONAL");
                return (
                  <li
                    key={action}
                    className={cn(
                      "px-2.5 py-2 text-2xs leading-relaxed",
                      provisional
                        ? "border border-dashed border-ink-faint/60 text-ink-faint"
                        : "border border-line bg-panel text-ink-dim",
                    )}
                  >
                    {action}
                  </li>
                );
              })}
            </ul>
          </Section>
        ) : null}

        <Section title="Proposed fix">
          {fix ? (
            <FixBlock fix={fix} />
          ) : fixLookup?.status === "loading" ? (
            <p className="text-2xs text-ink-faint">Loading fix results…</p>
          ) : fixLookup?.status === "error" ? (
            <p className="text-2xs text-ink-faint">
              Fix results could not be loaded: {fixLookup.message}
            </p>
          ) : (
            <p className="text-2xs leading-relaxed text-ink-faint">
              No fix pass has proposed a change for this artefact.{" "}
              <a href={hrefFor("fixes")} className="text-ink-dim underline">
                Verified Fixes
              </a>
            </p>
          )}
        </Section>
      </SheetContent>
    </Sheet>
  );
}
