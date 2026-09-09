# ADR-0014: QuantumBank and the honest KPI harness

* Status: accepted
* Date: 2026-09-09
* Slice: seeded repo + KPI harness (last pre-hackathon slice)

## Context

Every slice so far measured itself against its own fixtures. Nothing measured
ECDAT *as a whole* against a realistic estate, and a number nobody has computed
end to end is a number nobody should quote.

## Decision

### The answer key is the contract, and it lists what we cannot find

`testdata/quantumbank/answer_key.yaml` names every artefact planted in the
fixture — **including the ones ECDAT cannot detect.** Those carry
`known_gap: true`, are excluded from the recall denominator, and are **printed
every run** with the reason.

The alternative — quietly leaving undetectable crypto out of the fixture —
produces a better number by making the test easier. That is the oldest way to
lie with a benchmark, and it is the specific temptation a seeded repo creates,
because the person planting the artefacts is the person being scored.

QuantumBank's Go gateway signs partner callbacks with ECDSA P-256 and embeds a
PEM certificate. Scanner A is Python-only (ADR-0004), so ECDAT sees neither.
Both are in the fixture, both are `known_gap`, and both appear on every KPI
run. **A recall figure means nothing without the list of what it declined to
measure.**

### A decoy firing is a precision failure, counted

Not ignored as "not in the answer key". A false positive an operator chases and
finds nothing behind spends their trust, and trust is the thing a security tool
runs on. Precision is `(emitted − decoy_hits) / emitted`, and the gate is
exactly 1.0.

Precision is deliberately *not* "everything unlisted is false": the answer key
lists planted artefacts, not every finding a real scan legitimately produces,
so counting the unlisted as wrong would punish correct detections the fixture
happens not to enumerate.

### Every miss is named

Planted-but-not-found, fired-but-should-not-have, expected-drift-missing,
invented-drift, and every known gap. The table is the headline; the lists below
it are the honest part, and they are what belongs on a slide beside the number.

### The committed spool, and why the live proof stays separate

The observed view for the KPI is **committed JSONL** under
`testdata/quantumbank/spool/`. That makes the KPI deterministic, root-free and
runnable in CI. The live agent proof (`scripts/prove_pillar2.sh`, ADR-0010)
stays a separate, privileged, human-run thing.

Conflating them would mean either a KPI that needs root and a real handshake —
so it never runs — or a "live" proof that is really replaying a file. Two
claims, two mechanisms.

The harness **copies** the spool before scanning: the spool scanner moves
ingested files to `consumed/` (ADR-0010), which is right for a real seam and
would mutate a committed fixture and make the second run differ from the first.

### The gate

`recall >= 0.9` over the claimed-detectable set **and** `decoy precision == 1.0`.
Actual numbers are printed regardless of pass or fail — a gate that hides the
measurement when it fails is a gate that will be quietly loosened.

## What the first run found

The harness immediately reported **invented drift at `openssl@quantumbank`**,
and the tool was right and the answer key was wrong. `openssl.cnf` declares
`Groups = X25519MLKEM768` system-wide, the image ships libssl 3.0.2, and that
policy genuinely cannot be met. It had been written down as an *agreement case*
out of carelessness. The expectation was corrected, not the detection, and the
entry in the answer key now says so.

That is the argument for writing the answer key first, in one incident: the
contract caught its own author.

### A third category the run forced into existence

The same run produced drift at `legacy.quantumbank.invalid:8443` and a second
finding at `openssl@quantumbank` that is **neither expected nor invented**. The
observed view carries no endpoint (a uprobe sees a process, not a listening
socket — ADR-0012), so an observed handshake wildcard-joins every declared
endpoint and produces plausible but unattributable drift against the ones it did
not occur on.

Scoring those as correct would overstate the tool; scoring them as invented
would understate it. Neither is true, so they are `attribution_limited`:
excluded from precision and **printed every run** as `UNATTRIBUTABLE`, with the
ADR they come from. The fix is socket-level attribution in the probe.

## Measured

```
  view          planted   found    recall
  declared           14      14   100.0%
  shipped             3       3   100.0%
  observed            3       3   100.0%
  OVERALL            20      20   100.0%

  precision (decoys) : 100.0%  (0 decoy hits of 26 emitted)
  drift recall       : 100.0%  (3/3 expected)
  drift precision    : 100.0%  (0 invented)
  scan time          : ~2.5s   components: 26
  GATE: PASS
```

Both headline drifts found: `shipped-cannot-do-declared` and
`declared-pqc-observed-classical`, each at `payments.quantumbank.invalid:443`.

Two known gaps printed. Three unattributable drifts printed.

## Consequences

* One command (`make kpi`) produces the demo's central claim with its
  caveats attached, and two runs give identical numbers — the determinism
  invariants hold all the way from the scanners to the score.
* **100% recall is a statement about a fixture we wrote**, and should be quoted
  that way. It says the pipeline detects what it claims to detect on a
  realistic-but-small estate; it does not say ECDAT finds all cryptography.
  The known-gap and unattributable lines are what keep that distinction on the
  page rather than in a footnote.
* The scorer is separated from the scan and tested on synthetic inputs, because
  a generous scorer is the easiest way for a benchmark to become meaningless
  and the hardest to notice.
* QuantumBank is ~5 files of source, 4 configs, one image and two spool records
  — deliberately small enough to read in full. A fixture nobody reads is a
  fixture nobody can check.

## Alternatives considered

* **Leave undetectable artefacts out of the fixture.** Better number, less
  information, and it makes the KPI a measure of the fixture rather than of the
  tool. Rejected as the central thing this ADR exists to refuse.
* **Score precision against the full answer key.** Would require enumerating
  every legitimate finding of a real scan, and would mark correct detections
  wrong for being unlisted.
* **Use the live agent for the observed view.** A KPI that needs root and a real
  handshake is a KPI that runs once and then never again.
* **A larger, more realistic QuantumBank.** More impressive, and past a few
  hundred lines nobody verifies the answer key by hand — at which point the
  ground truth becomes an assumption.
