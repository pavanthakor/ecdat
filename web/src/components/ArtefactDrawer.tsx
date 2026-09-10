/**
 * The drill-down: everything ECDAT knows about one artefact, and how it knows.
 *
 * The section order is the argument a reviewer actually makes: WHAT was found,
 * WHERE it was seen (evidence first -- a claim without receipts is not a
 * claim), WHY it scored what it did, whether the views DISAGREE, and what to
 * do about it. Provenance rides on the score section, because that is where a
 * reader is deciding whether to believe a number.
 */
import { FileCode2, ShieldAlert } from "lucide-react";

import type { Artefact } from "@/api/types";
import { BAND_STYLE, cn } from "@/lib/format";
import { FactList, ProvenanceBadge } from "./Provenance";
import { Sheet, SheetContent } from "./ui/sheet";

interface Props {
  artefact: Artefact | null;
  onClose: () => void;
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

export function ArtefactDrawer({ artefact, onClose }: Props) {
  if (!artefact) return null;
  const style = BAND_STYLE[artefact.band];

  return (
    <Sheet open onOpenChange={(open) => !open && onClose()}>
      <SheetContent title={artefact.name} description={artefact.bomRef}>
        <div className="mb-5 flex flex-wrap items-center gap-2">
          <span
            className={cn(
              "flex items-baseline gap-2 border px-2.5 py-1",
              style.bg,
            )}
          >
            <span className={cn("font-mono text-lg tabular-nums", style.text)}>
              {artefact.score}
            </span>
            <span className={cn("text-2xs uppercase tracking-wide", style.text)}>
              {artefact.band}
            </span>
          </span>
          <ProvenanceBadge artefact={artefact} />
          {artefact.quantumStatus ? (
            <span className="border border-line bg-raised px-2 py-0.5 text-2xs uppercase tracking-wide text-ink-dim">
              quantum: {artefact.quantumStatus}
            </span>
          ) : null}
        </div>

        <div className="mb-5 grid grid-cols-2 gap-px border border-line bg-line text-xs sm:grid-cols-3">
          {[
            ["view", artefact.view],
            ["asset type", artefact.assetType],
            ["usage", artefact.usage],
            ["primitive", artefact.primitive ?? "—"],
            ["endpoint", artefact.endpoint ?? "—"],
            ["coverage", artefact.coverageViews.join(", ") || "—"],
          ].map(([label, value]) => (
            <div key={label} className="bg-panel px-2.5 py-1.5">
              <div className="text-2xs uppercase tracking-wide text-ink-faint">
                {label}
              </div>
              <div className="truncate font-mono text-ink-dim">{value}</div>
            </div>
          ))}
        </div>

        <Section title="Evidence" count={artefact.occurrences.length}>
          <ul className="space-y-1.5">
            {artefact.occurrences.map((occurrence, index) => (
              <li
                key={`${occurrence.locator}-${index}`}
                className="border border-line bg-panel px-2.5 py-2"
              >
                <div className="flex items-center gap-2">
                  <FileCode2
                    className="h-3 w-3 shrink-0 text-ink-faint"
                    aria-hidden
                  />
                  <span className="truncate font-mono text-2xs text-ink">
                    {occurrence.locator}
                  </span>
                  <span className="ml-auto shrink-0 border border-line px-1 text-[9px] uppercase tracking-wide text-ink-faint">
                    {occurrence.scanner || occurrence.view}
                  </span>
                </div>
                <div className="mt-1 font-mono text-2xs text-ink-faint">
                  {occurrence.detail}
                </div>
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
                  className="border border-high/40 bg-high/5 px-2.5 py-2"
                >
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="h-3 w-3 shrink-0 text-high" aria-hidden />
                    <span className="font-mono text-2xs text-high">{drift.kind}</span>
                  </div>
                  <div className="mt-1.5 grid grid-cols-2 gap-2 text-2xs">
                    <div>
                      <span className="text-ink-faint">declared </span>
                      <span className="font-mono text-ink">{drift.declared}</span>
                    </div>
                    <div>
                      <span className="text-ink-faint">observed </span>
                      <span className="font-mono text-ink">{drift.observed}</span>
                    </div>
                  </div>
                  <p className="mt-1.5 text-2xs leading-relaxed text-ink-dim">
                    {drift.cause}
                  </p>
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

        {artefact.fix ? (
          <Section title="Proposed fix">
            <div
              className={cn(
                "border px-2.5 py-2",
                artefact.fix.verified
                  ? "border-emerald-500/40 bg-emerald-500/5"
                  : "border-dashed border-ink-faint/60",
              )}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-2xs text-ink">
                  {artefact.fix.template}
                </span>
                <span
                  className={cn(
                    "text-2xs uppercase tracking-wide",
                    artefact.fix.verified ? "text-emerald-400" : "text-ink-faint",
                  )}
                >
                  {artefact.fix.verified ? "verified" : "not verified"}
                </span>
              </div>
              <p className="mt-1 text-2xs leading-relaxed text-ink-faint">
                {artefact.fix.reason}
              </p>
              {artefact.fix.diff ? (
                <pre className="mt-2 overflow-x-auto border border-line bg-ground p-2 font-mono text-2xs leading-relaxed">
                  {artefact.fix.diff.split("\n").map((line, index) => (
                    <div
                      key={index}
                      className={
                        line.startsWith("+")
                          ? "text-emerald-400"
                          : line.startsWith("-")
                            ? "text-critical"
                            : line.startsWith("@@")
                              ? "text-accent"
                              : "text-ink-faint"
                      }
                    >
                      {line}
                    </div>
                  ))}
                </pre>
              ) : null}
            </div>
          </Section>
        ) : null}
      </SheetContent>
    </Sheet>
  );
}
