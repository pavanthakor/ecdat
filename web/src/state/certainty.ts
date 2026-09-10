/**
 * How sure ECDAT is about one finding, in the console's words (ADR-0034).
 *
 * The CBOM carries `ecdat:confidence` on every component and
 * `ecdat:param:candidate` on a finding its rule calls a candidate. The console
 * READS both -- it never scores -- and puts every artefact in one of four
 * places:
 *
 * * **candidate** -- the rule FLAGGED it: a key-ish name holding a
 *   high-entropy literal nobody saw reach a crypto sink. It might not be real
 *   key material at all. The one state the Inventory table marks.
 * * **inferred** -- confidence below 1.0 without the flag: real crypto with one
 *   detail not read outright (a parameter that came through a variable, a
 *   binary heuristic). NOT a candidate, so the table does not shout about it;
 *   the drawer shows the confidence and why.
 * * **confirmed** -- confidence exactly 1.0, and no flag.
 * * **unrecorded** -- the document says nothing. Not a candidate, because no
 *   doubt was recorded, and not confirmed, because no certainty was either:
 *   inventing one for a missing property is what the console must never do.
 *
 * "Candidate" is a flag, not a number. The first version (0d22a73) tagged
 * everything below 1.0, which marked an ECDSA JWT whose algorithm is certain,
 * and every binary finding, as "might not be real".
 *
 * On screen the difference is border and weight and a word, never colour
 * (ADR-0031 §8): colour means severity and nothing else.
 */
import type { Artefact } from "@/api/types";

export type Certainty = "candidate" | "inferred" | "confirmed" | "unrecorded";

export function certaintyOf(artefact: Artefact): Certainty {
  if (artefact.candidate) return "candidate";
  if (artefact.confidence === null) return "unrecorded";
  return artefact.confidence < 1 ? "inferred" : "confirmed";
}

/** Every bucket, zeroes included -- the same rule as the band readout. */
export function certaintyCountsOf(artefacts: Artefact[]): Record<Certainty, number> {
  const counts: Record<Certainty, number> = {
    candidate: 0,
    inferred: 0,
    confirmed: 0,
    unrecorded: 0,
  };
  for (const artefact of artefacts) counts[certaintyOf(artefact)] += 1;
  return counts;
}

/** `1` -> `1.0`, `0.5` -> `0.5`, `0.95` -> `0.95`; nothing stored -> "not recorded". */
export function formatConfidence(confidence: number | null): string {
  if (confidence === null) return "not recorded";
  const text = String(confidence);
  return text.includes(".") ? text : confidence.toFixed(1);
}

/**
 * WHY, in a sentence, for the drawer.
 *
 * The candidate story -- a high-entropy literal nobody saw reach a sink -- is
 * told only for a finding its rule flagged as one. An inferred finding gets
 * its own, less specific sentence: the console does not know whether a
 * heuristic technique or an unresolved parameter put it below 1.0, and it does
 * not guess.
 */
export function certaintyReason(artefact: Artefact): string {
  const value = formatConfidence(artefact.confidence);
  switch (certaintyOf(artefact)) {
    case "candidate":
      return (
        `Candidate, confidence ${value}: a key-ish name holding a high-entropy literal ` +
        `that ECDAT did not see reach a crypto sink. Shown for review — not confirmed ` +
        `key material (ADR-0034).`
      );
    case "inferred":
      return (
        `Confidence ${value}: below 1.0, so the scanner inferred part of this rather ` +
        `than reading it outright — a heuristic technique, or a parameter it could not ` +
        `resolve to a constant. The evidence below names the scanner and the rule.`
      );
    case "unrecorded":
      return (
        "Confidence not recorded: the stored document carries none for this artefact, " +
        "so the console cannot say how sure the scanner was."
      );
    default:
      return `Confirmed, confidence ${value}: the detector read this directly from what it scanned.`;
  }
}
