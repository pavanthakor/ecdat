/**
 * OVERVIEW -- "Cryptographic Security Overview", rebuilt on the v2 mockup
 * (web/design-v2/ecdat-console-v2/overview.html; ADR-0038).
 *
 * The mockup's layout, top to bottom: five stat cards; risk trend, findings by
 * category and a gauge; the priority table beside the ops column. Every figure
 * is real or says why it is not (ADR-0031), and every band-derived figure is
 * counted from the document ON SCREEN, so the whole screen follows the Mosca
 * slider through a real rescore round trip (ADR-0016).
 *
 * Where the mockup draws something ECDAT does not compute, its place is kept
 * and filled with what IS computed, named for what it is:
 *
 * - "Risk trend / Average score": stored rows carry band counts, not an
 *   average, so the trend is Critical + High per stored scan of this target --
 *   and it takes two scans to be a trend.
 * - "Overall risk 63/100 Elevated": there is no weighted estate score. The
 *   gauge is the PEAK artefact score in the live document, in its band colour.
 * - The delta pills ("+6", "↑ 4 pts"): nothing computes a delta against a
 *   baseline (PUNCHLIST). The pills state each figure's basis, neutral.
 * - "Good morning, Alex": ECDAT has keys, not people (ADR-0035). The title is
 *   the screen's.
 *
 * Added to the mockup's ops column, because the Overview is where it lives:
 * the CRQC horizon, the Mosca control.
 */
import { ArrowRight, Download, GitCompareArrows, Radar, ShieldAlert, Table2, Workflow } from "lucide-react";
import { useMemo, useState } from "react";

import { cbomPath } from "@/api/client";
import { BANDS, type Artefact, type Band, type ScanSummary } from "@/api/types";
import { FileButton } from "@/components/FileButton";
import { MetricCard, NotComputed } from "@/components/Honest";
import { InfoTip } from "@/components/InfoTip";
import { ScreenHeader } from "@/components/Panel";
import { Slider } from "@/components/ui/slider";
import { PanelHead, tone, useGrown } from "@/components/v2";
import { cn, formatDate, shortLocator } from "@/lib/format";
import { hrefFor, navigate } from "@/lib/router";
import { certaintyOf, formatConfidence } from "@/state/certainty";
import { Z_MAX, Z_MIN, type ScanView } from "@/state/inventory";
import {
  agility,
  computed,
  driftMeasure,
  moscaSummary,
  notComputed,
  priorityQueue,
  quantumExposure,
  viewCoverage,
  type Agility,
  type Measured,
  type MoscaSummary,
  type Range,
} from "@/state/metrics";
import { bandCountsOf } from "@/state/presentation";

const MOSCA_EXPLAINER =
  "Mosca's inequality: if the years data must stay secret (x) plus the years " +
  "migration takes (y) exceed the years until a cryptographically relevant " +
  "quantum computer (z), data encrypted today is already exposed. Moving z " +
  "re-scores the stored inventory through the rescore endpoint; nothing is " +
  "re-scanned, and the original verdict stays on record.";

/** Slider tick marks, as horizons in years; labelled as calendar years. */
const TICKS = [5, 10, 15, 20].filter((z) => z >= Z_MIN && z <= Z_MAX);

function locationOf(artefact: Artefact): string {
  return (
    artefact.endpoint ??
    (artefact.occurrences[0] ? shortLocator(artefact.occurrences[0].locator) : "no location")
  );
}

// ---------------------------------------------------------------------------
// Risk trend: Critical + High per stored scan of this target
// ---------------------------------------------------------------------------

function trendOf(scans: ScanSummary[], scan: ScanSummary): ScanSummary[] {
  return scans
    .filter(
      (row) =>
        row.kind === "scan" &&
        row.target.ref === scan.target.ref &&
        row.target.system === scan.target.system &&
        row.created_at <= scan.created_at,
    )
    .sort((a, b) => a.created_at.localeCompare(b.created_at))
    .slice(-8);
}

const severe = (row: ScanSummary) => (row.band_counts?.Critical ?? 0) + (row.band_counts?.High ?? 0);

function RiskTrend({ scans, scan }: { scans: ScanSummary[]; scan: ScanSummary }) {
  const points = trendOf(scans, scan);
  const target = scan.target.system ?? scan.target.ref;
  const head = (
    <PanelHead
      title="Risk trend"
      sub={
        points.length < 2
          ? "Critical + High, per stored scan"
          : `Critical + High, last ${points.length} stored scans`
      }
    />
  );

  if (points.length < 2) {
    return (
      <section className="panel in" data-testid="risk-trend" data-state="not-computed">
        {head}
        <div className="empty-inline">
          <NotComputed
            reason={`${points.length} stored scan of ${target} — a trend needs two. Each new scan of this target adds a point.`}
          />
        </div>
      </section>
    );
  }

  const values = points.map(severe);
  const max = Math.max(1, ...values);
  const W = 300;
  const H = 110;
  const xy = values.map((value, index) => [
    6 + (index / (values.length - 1)) * (W - 12),
    H - 8 - (value / max) * (H - 26),
  ]);
  const line = xy.map(([x, y], index) => `${index ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`).join(" ");
  const last = xy[xy.length - 1];
  const area = `${line} L${last[0].toFixed(1)} ${H} L${xy[0][0].toFixed(1)} ${H} Z`;

  return (
    <section className="panel in" data-testid="risk-trend" data-state="computed">
      {head}
      <div className="breakdown-value" data-testid="risk-trend-value">
        {values[values.length - 1]}
      </div>
      <svg
        className="breakdown-chart"
        viewBox={`0 0 ${W} ${H}`}
        width="100%"
        role="img"
        aria-label={`Critical + High per stored scan: ${values.join(", ")}`}
      >
        <title>Each point is a stored scan, counted at the horizon it was scored at.</title>
        <defs>
          <linearGradient id="trend-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#f5f6f8" stopOpacity="0.12" />
            <stop offset="1" stopColor="#f5f6f8" stopOpacity="0" />
          </linearGradient>
        </defs>
        <path d={area} fill="url(#trend-fill)" />
        <path d={line} fill="none" stroke="#9ba7b2" strokeWidth="1.6" strokeLinejoin="round" />
        <circle cx={last[0]} cy={last[1]} r="4" fill="#08090b" stroke="#f5f6f8" strokeWidth="2" />
      </svg>
      <div className="chart-axis">
        <span>{formatDate(points[0].created_at)}</span>
        <span>{formatDate(points[points.length - 1].created_at)}</span>
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Findings by category
// ---------------------------------------------------------------------------

interface Category {
  id: string;
  label: string;
  title: string;
  primitives?: string[];
}

/** CycloneDX primitive -> the mockup's groups. Anything else is "Other". */
const CATEGORIES: Category[] = [
  { id: "sig", label: "Sig", title: "Signature", primitives: ["signature"] },
  {
    id: "kex",
    label: "KEx",
    title: "Key exchange: KEM, key agreement, public-key encryption",
    primitives: ["kem", "key-agree", "key-agreement", "pke"],
  },
  {
    id: "sym",
    label: "Sym",
    title: "Symmetric: block and stream ciphers, AEAD, MAC",
    primitives: ["block-cipher", "stream-cipher", "ae", "mac"],
  },
  { id: "hash", label: "Hash", title: "Hash, XOF and KDF", primitives: ["hash", "xof", "kdf"] },
  { id: "proto", label: "Proto", title: "Protocols (TLS, SSH, ...): CycloneDX assetType protocol" },
  { id: "other", label: "Other", title: "Everything else: random-number generators, certificates, related material" },
];

function categoryOf(artefact: Artefact): string {
  if (artefact.assetType === "protocol") return "proto";
  const primitive = artefact.primitive;
  const hit = CATEGORIES.find((c) => primitive !== null && c.primitives?.includes(primitive));
  return hit?.id ?? "other";
}

function FindingsByCategory({ artefacts }: { artefacts: Artefact[] }) {
  const grown = useGrown();
  const counts = useMemo(() => {
    const table = Object.fromEntries(
      CATEGORIES.map((c) => [c.id, { Critical: 0, High: 0, Medium: 0, Low: 0 }]),
    ) as Record<string, Record<Band, number>>;
    for (const artefact of artefacts) table[categoryOf(artefact)][artefact.band] += 1;
    return table;
  }, [artefacts]);
  // "Other" earns a column only when something is in it.
  const shown = CATEGORIES.filter((c) => c.id !== "other" || BANDS.some((band) => counts.other[band] > 0));
  const peak = Math.max(1, ...shown.flatMap((c) => BANDS.map((band) => counts[c.id][band])));

  return (
    <section className="panel in" data-testid="findings-by-category" style={{ animationDelay: "0.06s" }}>
      <PanelHead title="Findings by category" sub="Signature · Key exchange · Symmetric · Hash · Protocol" />
      {artefacts.length === 0 ? (
        <div className="empty-inline">
          <NotComputed reason="this scan holds no artefacts" />
        </div>
      ) : (
        <>
          <div className="bars-wrap">
            {shown.map((category) => (
              <div key={category.id} className="bar-group" data-testid={`category-${category.id}`}>
                <div className="bar-stack" title={category.title}>
                  {BANDS.map((band) => {
                    const n = counts[category.id][band];
                    return (
                      <div
                        key={band}
                        data-band={band}
                        data-count={n}
                        title={`${category.title} · ${band}: ${n}`}
                        className={cn("bar", n > 0 && `band-bg-${tone(band)}`)}
                        style={{ height: grown && n > 0 ? `${(n / peak) * 100}%` : 0 }}
                      />
                    );
                  })}
                </div>
                <span className="bar-month">{category.label}</span>
              </div>
            ))}
          </div>
          <div className="band-key">
            {BANDS.map((band) => (
              <span key={band}>
                <i className={`swatch band-bg-${tone(band)}`} data-band={band} aria-hidden />
                {band}
              </span>
            ))}
          </div>
        </>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Peak risk gauge
// ---------------------------------------------------------------------------

const ARC = "M 25 90 A 60 60 0 0 1 145 90";
const ARC_LENGTH = 188.5;

function PeakRisk({ artefacts }: { artefacts: Artefact[] }) {
  const grown = useGrown();
  const peak = useMemo(() => priorityQueue(artefacts, 1)[0] ?? null, [artefacts]);
  const head = <PanelHead title="Peak risk" sub="Highest artefact score, live horizon" />;

  if (!peak) {
    return (
      <section className="panel in" data-testid="peak-risk" data-state="not-computed">
        {head}
        <div className="empty-inline">
          <NotComputed reason="this scan holds no artefacts to score" />
        </div>
      </section>
    );
  }

  return (
    <section
      className="panel in"
      data-testid="peak-risk"
      data-state="computed"
      style={{ animationDelay: "0.12s" }}
    >
      {head}
      <div className="gauge-panel">
        <div className="gauge-svg-wrap">
          <svg width="170" height="100" viewBox="0 0 170 100" aria-hidden>
            <path d={ARC} fill="none" stroke="#171c21" strokeWidth="12" strokeLinecap="round" />
            <path
              d={ARC}
              data-band={peak.band}
              className={`arc band-stroke-${tone(peak.band)}`}
              fill="none"
              strokeWidth="12"
              strokeLinecap="round"
              strokeDasharray={ARC_LENGTH}
              strokeDashoffset={ARC_LENGTH * (1 - (grown ? peak.score : 0) / 100)}
            />
          </svg>
          <div className="gauge-center">
            <div className="gauge-num" data-testid="peak-score">
              {peak.score}
            </div>
            <div className="gauge-lbl">/ 100 · {peak.band}</div>
          </div>
        </div>
        <div className="gauge-scale w-[170px]">
          <span>0</span>
          <span>100</span>
        </div>
        <a
          className="gauge-note hover:text-ink"
          href={hrefFor("inventory", { ref: peak.bomRef })}
          title={`${peak.name} at ${locationOf(peak)}`}
        >
          {peak.name} · {locationOf(peak)}
        </a>
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Priority findings
// ---------------------------------------------------------------------------

function PriorityRow({ artefact }: { artefact: Artefact }) {
  const certainty = certaintyOf(artefact);
  const place = locationOf(artefact);
  const filled = Math.max(1, Math.round((artefact.score / 100) * 6));
  const open = () => navigate("inventory", { ref: artefact.bomRef });

  return (
    <tr
      data-testid="priority-row"
      data-ref={artefact.bomRef}
      data-band={artefact.band}
      data-certainty={certainty}
      onClick={open}
    >
      <td>
        <a
          href={hrefFor("inventory", { ref: artefact.bomRef })}
          onClick={(event) => event.stopPropagation()}
          className={cn(
            "qt-mono hover:text-ink",
            // Weight, not colour: a candidate never reads as the strongest thing in its row.
            certainty === "candidate" ? "font-medium opacity-80" : "font-semibold",
          )}
        >
          {artefact.name}
        </a>
        <span className="ml-2 inline-flex flex-wrap gap-1 align-middle">
          {certainty === "candidate" ? (
            <span
              className="mark candidate"
              data-testid="candidate-tag"
              title={`Candidate: confidence ${formatConfidence(artefact.confidence)}. Shown for review, not a confirmed finding (ADR-0034).`}
            >
              candidate
            </span>
          ) : null}
          {certainty === "inferred" ? (
            <span className="mark" title={`Inferred: confidence ${formatConfidence(artefact.confidence)}`}>
              inferred
            </span>
          ) : null}
          {artefact.provisional ? (
            <span
              className="mark candidate"
              title="Provisional: part of this verdict rests on an unverified fact, which scored 0"
            >
              provisional
            </span>
          ) : null}
          {artefact.drift.length > 0 ? <span className="mark">drift</span> : null}
        </span>
      </td>
      <td className="qt-muted qt-mono" title={place}>
        {place}
      </td>
      <td>
        <span
          className={`qt-bar band-fg-${tone(artefact.band)}`}
          data-band={artefact.band}
          role="img"
          aria-label={`score ${artefact.score} of 100`}
        >
          {Array.from({ length: 6 }, (_, index) => (
            <i key={index} className={cn("qt-tick", index < filled && "fill")} />
          ))}
        </span>
      </td>
      <td className="font-bold tabular-nums">{artefact.score}</td>
      <td>
        <span className={`badge badge-${tone(artefact.band)}`} data-band={artefact.band}>
          {artefact.band}
        </span>
      </td>
    </tr>
  );
}

function PriorityFindings({ artefacts }: { artefacts: Artefact[] }) {
  const [band, setBand] = useState<Band | "all">("all");
  const rows = useMemo(
    () => priorityQueue(band === "all" ? artefacts : artefacts.filter((a) => a.band === band), 6),
    [artefacts, band],
  );

  return (
    <section className="panel in" data-testid="priority-findings" style={{ animationDelay: "0.18s" }}>
      <PanelHead
        title="Priority findings"
        sub="Highest risk, this scan at the live horizon"
        right={
          <div className="flex shrink-0 items-center gap-3">
            <select
              aria-label="Priority band"
              className="panel-select"
              value={band}
              onChange={(event) => setBand(event.target.value as Band | "all")}
            >
              <option value="all">All bands</option>
              {BANDS.map((b) => (
                <option key={b} value={b}>
                  {b}
                </option>
              ))}
            </select>
            <a className="panel-link inline-flex items-center gap-1" href={hrefFor("inventory")}>
              View inventory <ArrowRight className="h-3 w-3" aria-hidden />
            </a>
          </div>
        }
      />
      {rows.length === 0 ? (
        <div className="empty-inline" data-testid="priority-empty">
          <p className="empty-title">
            {band === "all" ? "This scan found no cryptographic artefacts" : `No ${band} findings at this horizon`}
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="queue-table">
            <thead>
              <tr>
                <th>Artefact</th>
                <th>Location</th>
                <th>Score</th>
                <th>Risk</th>
                <th>Band</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((artefact) => (
                <PriorityRow key={artefact.bomRef} artefact={artefact} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// The ops column: CRQC horizon, then crypto agility
// ---------------------------------------------------------------------------

function yearsText(range: Range): string {
  return range.min === range.max ? `${range.min} years` : `${range.min}–${range.max} years`;
}

function Term({ label, measured }: { label: string; measured: Measured<Range> }) {
  return (
    <div className="min-w-0">
      <div className="term-label">{label}</div>
      {measured.status === "computed" ? (
        <div className="term-value">{yearsText(measured.value)}</div>
      ) : (
        <NotComputed reason={measured.reason} className="mt-1.5" />
      )}
    </div>
  );
}

/**
 * The Mosca control. Changing z re-scores the STORED document through
 * `POST /scans/{id}/rescore` -- a new linked row, never an edit.
 */
function CrqcHorizon({
  view,
  live,
  mosca,
}: {
  view: ScanView;
  live: Record<Band, number>;
  mosca: MoscaSummary;
}) {
  const baseYear = new Date().getUTCFullYear();
  const delta = mosca.delta.status === "computed" ? mosca.delta.value : null;

  return (
    <section className="panel in" data-testid="crqc-horizon" style={{ animationDelay: "0.24s" }}>
      <PanelHead
        title={
          <>
            CRQC horizon <InfoTip label={MOSCA_EXPLAINER} />
          </>
        }
        sub="Mosca: exposed today when x + y > z"
        right={
          delta === null ? null : (
            <span className={cn("risk-flag", delta.exposed > 0 && "at-risk")}>
              {delta.exposed > 0 ? "At risk" : "Within horizon"}
            </span>
          )
        }
      />
      <div className="metric-hero">
        <span className={cn("metric-hero-num", view.rescoring && "text-ink-dim")}>{baseYear + view.zYears}</span>
        <span className="metric-hero-tag">z = {view.zYears} years</span>
      </div>
      <div className="metric-hero-note">
        {delta === null
          ? "affected findings not computed"
          : `${delta.exposed} of ${delta.assessed} findings exposed at this horizon`}
        {view.rescoring ? " · re-scoring the stored CBOM…" : ""}
      </div>

      <div className="mt-5">
        <Slider
          value={[view.zYears]}
          min={Z_MIN}
          max={Z_MAX}
          step={1}
          aria-label="Years until a cryptographically relevant quantum computer"
          onValueChange={([value]) => view.setZYears(value)}
        />
        <div className="slider-scale">
          {TICKS.map((z) => (
            <span
              key={z}
              className={cn(
                "absolute -translate-x-1/2",
                z === Z_MIN && "translate-x-0",
                z === Z_MAX && "-translate-x-full",
                z === view.zYears && "font-semibold text-ink",
              )}
              style={{ left: `${((z - Z_MIN) / (Z_MAX - Z_MIN)) * 100}%` }}
            >
              {baseYear + z}
            </span>
          ))}
        </div>
      </div>

      <div data-testid="live-readout" className={cn("readout", view.rescoring && "opacity-40")}>
        {BANDS.map((band) => (
          <div key={band}>
            <i className={`swatch band-bg-${tone(band)}`} data-band={band} aria-hidden />
            <div data-testid={`live-${band}`} className="readout-num">
              {live[band]}
            </div>
            <div className="readout-lbl">{band}</div>
          </div>
        ))}
      </div>

      <div className="terms">
        <Term label="Data shelf life" measured={mosca.x} />
        <Term label="Migration time" measured={mosca.y} />
        <div data-testid="horizon-delta" className="min-w-0">
          <div className="term-label">Horizon delta</div>
          {delta !== null ? (
            <>
              {/* Negative means exposed today: said by weight, not red. */}
              <div className={cn("term-value", delta.worst < 0 && "font-bold")}>
                {delta.worst > 0 ? `+${delta.worst}` : delta.worst} years
              </div>
              <div className="term-note">z − (x + y), worst component</div>
            </>
          ) : mosca.delta.status === "not-computed" ? (
            <NotComputed reason={mosca.delta.reason} className="mt-1.5" />
          ) : null}
        </div>
      </div>
    </section>
  );
}

function AgilityPanel({ agile }: { agile: Agility }) {
  const assessed = agile.configurable + agile.hardCoded;
  return (
    <section className="panel in" data-testid="overview-agility" style={{ animationDelay: "0.3s" }}>
      <PanelHead
        title="Crypto agility"
        sub="Configurable vs hard-coded"
        right={
          <a className="panel-link" href={hrefFor("agility")}>
            Details
          </a>
        }
      />
      {agile.share.status === "computed" ? (
        <>
          <div className="ops-value">
            <span data-testid="agility-share">{agile.share.value}%</span>
            <span className="ops-pill" title={agile.share.basis}>
              {agile.configurable} of {assessed} assessed
            </span>
          </div>
          <div
            className="split-track"
            role="img"
            aria-label={`${agile.configurable} configurable, ${agile.hardCoded} hard-coded, ${agile.unassessed} not assessed`}
          >
            {agile.configurable > 0 ? <span style={{ flexGrow: agile.configurable, background: "#f5f6f8" }} /> : null}
            {agile.hardCoded > 0 ? <span style={{ flexGrow: agile.hardCoded, background: "#5f6b76" }} /> : null}
            {agile.unassessed > 0 ? (
              <span
                style={{
                  flexGrow: agile.unassessed,
                  backgroundImage: "repeating-linear-gradient(90deg, #242b31 0 3px, transparent 3px 6px)",
                }}
              />
            ) : null}
          </div>
          <div className="split-legend">
            <span>
              <b data-testid="overview-configurable">{agile.configurable}</b> configurable
            </span>
            <span>
              <b>{agile.hardCoded}</b> hard-coded
            </span>
            <span title="No scanner determined configurability. Not counted as hard-coded.">
              <b>{agile.unassessed}</b> not assessed
            </span>
          </div>
        </>
      ) : (
        <div className="empty-inline">
          <NotComputed reason={agile.share.reason} />
        </div>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// The screen
// ---------------------------------------------------------------------------

export function OverviewScreen({ view }: { view: ScanView }) {
  const { scan, artefacts, loading } = view;

  const live = useMemo(() => bandCountsOf(artefacts), [artefacts]);
  const mosca = useMemo(() => moscaSummary(artefacts), [artefacts]);
  const quantum = useMemo(() => quantumExposure(artefacts), [artefacts]);
  const coverage = useMemo(() => viewCoverage(artefacts), [artefacts]);
  const agile = useMemo(() => agility(artefacts), [artefacts]);
  const drift = driftMeasure(scan, artefacts);

  const header = (
    <ScreenHeader
      title="Cryptographic Security Overview"
      actions={
        scan ? (
          <FileButton
            path={cbomPath(scan.id)}
            filename={`ecdat-cbom-${scan.id.slice(0, 8)}.json`}
            title="Download the stored CBOM this overview is computed from"
            bare
            className="btn-ghost"
          >
            <Download className="h-3.5 w-3.5" aria-hidden /> Export snapshot
          </FileButton>
        ) : undefined
      }
    />
  );

  if (loading && artefacts.length === 0) {
    return (
      <div className="content">
        {header}
        <div className="stat-row">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="stat-card h-[5.75rem] animate-pulse" />
          ))}
        </div>
        <div className="grid-row grid-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="panel h-60 animate-pulse" />
          ))}
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="content">
        {header}
        <div className="empty-state">
          <p className="empty-title">No scan in this database</p>
          <p className="empty-text">
            Nothing to summarise yet. Use <strong className="text-ink-dim">Run scan</strong>, or run{" "}
            <code className="mono">ecdat scan</code> against the same <code className="mono">ECDAT_DB</code> the
            server opened.
          </p>
        </div>
      </div>
    );
  }

  const total = artefacts.length;
  const share = (n: number) => (total === 0 ? 0 : Math.round((n / total) * 100));
  const quantumMeasure: Measured<number> =
    total === 0
      ? notComputed("this scan holds no artefacts")
      : computed(
          quantum.broken,
          `${share(quantum.broken)}% of inventory broken by Shor · ${quantum.weakened} weakened · ${quantum.unassessed} without a verdict`,
        );
  const views = `${coverage.collected.length} of 3 views`;

  return (
    <div className="content">
      {header}
      <div className={cn("transition-opacity", view.rescoring && "opacity-70")}>
        <div className="stat-row in">
          <MetricCard
            id="total"
            label="Artefacts"
            icon={<Table2 className="h-[13px] w-[13px]" />}
            measured={computed(total, `across ${coverage.collected.length} of 3 evidence layers`)}
            note="total"
          />
          <MetricCard
            id="quantum"
            label="Quantum vulnerable"
            icon={<ShieldAlert className="h-[13px] w-[13px]" />}
            pad
            measured={quantumMeasure}
            note={`${share(quantum.broken)}% of total`}
          />
          <MetricCard
            id="drift"
            label="Drift findings"
            icon={<GitCompareArrows className="h-[13px] w-[13px]" />}
            pad
            measured={drift}
            note={drift.status === "computed" && drift.value === 0 ? "views agree" : `${views} compared`}
          />
          <MetricCard
            id="coverage"
            label="Coverage"
            icon={<Radar className="h-[13px] w-[13px]" />}
            unit="%"
            measured={coverage.share}
            note={views}
          />
          <MetricCard
            id="agility"
            label="Crypto agility"
            icon={<Workflow className="h-[13px] w-[13px]" />}
            unit="%"
            measured={agile.share}
            note={`${agile.configurable} of ${agile.configurable + agile.hardCoded}`}
          />
        </div>

        <div className="grid-row grid-3">
          <RiskTrend scans={view.scans} scan={scan} />
          <FindingsByCategory artefacts={artefacts} />
          <PeakRisk artefacts={artefacts} />
        </div>

        <div className="grid-row grid-2b">
          <PriorityFindings artefacts={artefacts} />
          <div className="stack">
            <CrqcHorizon view={view} live={live} mosca={mosca} />
            <AgilityPanel agile={agile} />
          </div>
        </div>
      </div>
    </div>
  );
}
