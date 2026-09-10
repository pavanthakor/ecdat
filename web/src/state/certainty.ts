/**
 * How sure ECDAT is about one finding, in the console's words (ADR-0034).
 *
 * The CBOM carries `ecdat:confidence` on every component and
 * `ecdat:param:candidate` on a finding its rule calls a candidate. The console
 * READS both -- it never scores -- and puts every artefact in one of three
 * places:
 *
 * * **candidate** -- confidence below 1.0, or the candidate flag. Shown,
 *   marked uncertain, never rendered as a confident assertion.
 * * **confirmed** -- confidence exactly 1.0, and no flag.
 * * **unrecorded** -- the document says nothing. Not a candidate, because no
 *   doubt was recorded, and not confirmed, because no certainty was either:
 *   inventing one for a missing property is what the console must never do.
 *
 * On screen the difference is border and weight and a word, never colour
 * (ADR-0031 §8): colour means severity and nothing else.
 */
import type { Artefact } from "@/api/types";

export type Certainty = "candidate" | "confirmed" | "unrecorded";

export function certaintyOf(artefact: Artefact): Certainty {
  if (artefact.candidate) return "candidate";
  if (artefact.confidence === null) return "unrecorded";
  return artefact.confidence < 1 ? "candidate" : "confirmed";
}

/** Every bucket, zeroes included -- the same rule as the band readout. */
export function certaintyCountsOf(artefacts: Artefact[]): Record<Certainty, number> {
  const counts: Record<Certainty, number> = { candidate: 0, confirmed: 0, unrecorded: 0 };
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
 * told only for a finding its rule flagged as one. A finding below 1.0 for
 * another reason (a heuristic binary technique, or a parameter that never
 * resolved to a constant) gets its own, less specific sentence: the console
 * does not know which of the two it was, and it does not guess.
 */
export function certaintyReason(artefact: Artefact): string {
  const value = formatConfidence(artefact.confidence);
  if (artefact.candidate) {
    return (
      `Candidate, confidence ${value}: a key-ish name holding a high-entropy literal ` +
      `that ECDAT did not see reach a crypto sink. Shown for review — not confirmed ` +
      `key material (ADR-0034).`
    );
  }
  switch (certaintyOf(artefact)) {
    case "candidate":
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
