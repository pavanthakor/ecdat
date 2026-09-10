/**
 * Verified vs provisional, as a visual (ADR-0017 -> ADR-0018).
 *
 * The policy engine already refuses to let an unverified fact move a number.
 * This is the other half of that promise: **a fact nobody checked must never
 * LOOK like a checked one.** A deadline rendered identically whether or not
 * anybody confirmed it is a deadline somebody will plan around.
 *
 * The treatment is deliberately not a colour. Colour in this console means
 * severity and nothing else, so provenance is carried by BORDER and WEIGHT --
 * verified is solid and full-contrast, provisional is dashed and desaturated,
 * and the word "provisional" is always present in the text rather than only in
 * a tooltip. A caveat that needs a hover is a caveat that will be missed on a
 * projector.
 */
import { AlertTriangle, ShieldCheck } from "lucide-react";

import type { Artefact } from "@/api/types";
import { cn } from "@/lib/format";

const PROVISIONAL =
  "border border-dashed border-ink-faint/60 text-ink-faint bg-transparent";
const VERIFIED = "border border-line bg-raised text-ink";

function provisionalTitle(artefact: Artefact): string {
  return (
    `Provisional: this verdict includes ${artefact.provisionalRules.length} ` +
    `rule(s) that have not been confirmed against their source, so they ` +
    `contributed 0 to the score — ${artefact.provisionalRules.join(", ")}`
  );
}

/**
 * The component-level provenance stamp: is anything here unconfirmed?
 */
export function ProvenanceBadge({ artefact }: { artefact: Artefact }) {
  const isProvisional = artefact.provisional;
  return (
    <span
      data-testid="provenance"
      data-provenance={isProvisional ? "provisional" : "verified"}
      title={
        isProvisional
          ? provisionalTitle(artefact)
          : "Verified: every rule behind this score cites a source that was checked."
      }
      className={cn(
        "inline-flex items-center gap-1.5 px-2 py-0.5 text-2xs font-medium tracking-wide uppercase",
        isProvisional ? PROVISIONAL : VERIFIED,
      )}
    >
      {isProvisional ? (
        <AlertTriangle className="h-3 w-3" aria-hidden />
      ) : (
        <ShieldCheck className="h-3 w-3 text-emerald-400/80" aria-hidden />
      )}
      {isProvisional ? "Provisional" : "Verified"}
    </span>
  );
}

/**
 * Which rules fired, and what each one actually contributed.
 *
 * An unverified rule is listed -- demoted, never dropped -- and states
 * "scored 0" where a verified rule states its category. That wording is the
 * point: the reader learns the rule exists AND that it moved nothing.
 */
export function FactList({ artefact }: { artefact: Artefact }) {
  const provisionalRules = new Set(artefact.provisionalRules);

  return (
    <div className="space-y-4">
      <section>
        <h4 className="mb-2 text-2xs font-semibold uppercase tracking-widest text-ink-faint">
          Score breakdown
        </h4>
        <div
          data-testid="category-breakdown"
          className="grid grid-cols-2 gap-px border border-line bg-line"
        >
          {artefact.categories.map((entry) => (
            <div
              key={entry.category}
              data-testid={`category-${entry.category}`}
              className="flex items-baseline justify-between bg-panel px-2.5 py-1.5"
            >
              <span className="text-2xs uppercase tracking-wide text-ink-dim">
                {entry.category}
              </span>
              <span
                className={cn(
                  "font-mono text-sm tabular-nums",
                  entry.score === 0 ? "text-ink-faint" : "text-ink",
                )}
              >
                {entry.score}
              </span>
            </div>
          ))}
          <div className="col-span-2 flex items-baseline justify-between border-t border-line bg-raised px-2.5 py-1.5">
            <span className="text-2xs font-semibold uppercase tracking-widest text-ink-dim">
              Total
            </span>
            <span className="font-mono text-base font-medium tabular-nums text-ink">
              {artefact.score}
            </span>
          </div>
        </div>
      </section>

      <section>
        <h4 className="mb-2 flex items-center justify-between text-2xs font-semibold uppercase tracking-widest text-ink-faint">
          <span>Fired rules</span>
          <span className="font-mono normal-case tracking-normal">
            {artefact.firedRules.length}
          </span>
        </h4>
        <ul className="space-y-1">
          {artefact.firedRules.map((rule) => {
            const unverified = provisionalRules.has(rule);
            return (
              <li
                key={rule}
                data-testid={`fact-${rule}`}
                data-provenance={unverified ? "provisional" : "verified"}
                className={cn(
                  "flex items-center justify-between gap-3 px-2.5 py-1.5 text-xs",
                  unverified ? PROVISIONAL : "border border-line bg-panel",
                )}
              >
                <span className="truncate font-mono">{rule}</span>
                <span
                  data-testid="fact-contribution"
                  className={cn(
                    "shrink-0 text-2xs uppercase tracking-wide",
                    unverified ? "text-ink-faint" : "text-ink-dim",
                  )}
                >
                  {unverified ? "provisional · scored 0" : ruleCategory(artefact, rule)}
                </span>
              </li>
            );
          })}
        </ul>
      </section>

      <section>
        <h4 className="mb-2 text-2xs font-semibold uppercase tracking-widest text-ink-faint">
          Deadline
        </h4>
        <div
          data-testid="deadline"
          data-provenance={artefact.deadlineProvisional ? "provisional" : "verified"}
          className={cn(
            "flex items-baseline justify-between px-2.5 py-2",
            artefact.deadlineProvisional ? PROVISIONAL : VERIFIED,
          )}
        >
          <span className="font-mono text-sm">{artefact.deadline ?? "none"}</span>
          <span className="text-2xs uppercase tracking-wide">
            {artefact.deadlineProvisional
              ? "provisional — unconfirmed source"
              : "verified"}
          </span>
        </div>
      </section>
    </div>
  );
}

/**
 * Which category a rule contributed to.
 *
 * Derived from the rule id prefix against the categories the engine actually
 * reported, so it is a lookup rather than a guess -- and it falls back to
 * "scored" rather than inventing a category when the two do not line up.
 */
function ruleCategory(artefact: Artefact, rule: string): string {
  const prefix = rule.split("-")[0];
  const match = artefact.categories.find(
    (entry) => entry.category === prefix || rule.startsWith(entry.category),
  );
  if (match) return `${match.category} · ${match.score}`;
  if (rule.startsWith("dst")) {
    const criticality = artefact.categories.find(
      (entry) => entry.category === "criticality",
    );
    return criticality ? `criticality · ${criticality.score}` : "scored";
  }
  if (rule.startsWith("nist") || rule.startsWith("exposure")) {
    const exposure = artefact.categories.find(
      (entry) => entry.category === "exposure",
    );
    return exposure ? `exposure · ${exposure.score}` : "scored";
  }
  return "scored";
}
