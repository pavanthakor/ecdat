/**
 * REPORTS -- the three PDFs (ADR-0020) and the offline export formats.
 *
 * Every report is rendered ON REQUEST from the stored CBOM by
 * `GET /scans/{id}/report/{kind}`: nothing is re-scanned, so a report cannot
 * disagree with this console for the same scan. Formats with no renderer say
 * so; CSV is a browser-side projection of the stored values, labelled as such.
 */
import { Download, ExternalLink } from "lucide-react";

import { cbomUrl, reportUrl } from "@/api/client";
import type { Artefact, ReportKind, ScanSummary } from "@/api/types";
import { EmptyPanel, NotComputed } from "@/components/Honest";
import { Button, LinkButton, Panel, ScreenHeader, Tag } from "@/components/Panel";
import { downloadText } from "@/screens/Inventory";
import { inventoryCsv, sortByRisk } from "@/state/metrics";

/** Summaries of reports/executive.py, technical.py and coverage.py. */
const REPORTS: { kind: ReportKind; title: string; audience: string; body: string }[] = [
  {
    kind: "executive",
    title: "Executive summary",
    audience: "Decision-makers",
    body: "Two pages a decision-maker can act on: the estate's shape, the five artefacts that decide the migration plan, and the deadline the organisation is measured against. Provisional facts are labelled in the text.",
  },
  {
    kind: "technical",
    title: "Technical detail",
    audience: "Engineers and reviewers",
    body: "Every artefact with its receipts: what was found, where it was seen, why it scored what it did, whether the views disagree, and what a verified fix would change. Grouped by band, each section with its own count.",
  },
  {
    kind: "coverage",
    title: "Coverage statement",
    audience: "Auditors — and anyone reading the other two",
    body: "What this scan did not look at: which scanners ran, which views were and were not collected, components with an incomplete cross-view group, and the limits that hold for every scan.",
  },
];

export function ReportsScreen({ scan, artefacts }: { scan: ScanSummary | null; artefacts: Artefact[] }) {
  const short = scan?.id.slice(0, 8) ?? "";
  return (
    <div>
      <ScreenHeader
        title="Reports"
        subtitle="Rendered on request from the stored CBOM — nothing is re-scanned, so a report cannot disagree with this console for the same scan. Every format is produced locally; nothing leaves the machine."
      />
      {!scan ? (
        <div className="p-4">
          <EmptyPanel title="No scan selected" />
        </div>
      ) : (
        <div className="space-y-3 p-4">
          <div className="grid gap-3 lg:grid-cols-3">
            {REPORTS.map((report) => (
              <Panel key={report.kind} title={report.title} meta={<Tag>PDF</Tag>} testId={`report-${report.kind}`}>
                <div className="eyebrow">{report.audience}</div>
                <p className="mt-1.5 min-h-[5.5rem] text-2xs leading-relaxed text-ink-dim">{report.body}</p>
                <div className="mt-3 flex gap-2">
                  <LinkButton href={reportUrl(scan.id, report.kind)} target="_blank" rel="noopener">
                    <ExternalLink className="h-3 w-3" aria-hidden /> View
                  </LinkButton>
                  <LinkButton
                    href={reportUrl(scan.id, report.kind)}
                    download={`qorbit-${report.kind}-${short}.pdf`}
                  >
                    <Download className="h-3 w-3" aria-hidden /> Generate PDF
                  </LinkButton>
                </div>
              </Panel>
            ))}
          </div>

          <Panel title="Offline export formats" bodyClassName="p-0">
            <ul className="divide-y divide-line-soft">
              <li className="grid grid-cols-[10rem_1fr_auto] items-center gap-3 px-3 py-2">
                <span className="text-xs font-medium text-ink">CBOM · JSON</span>
                <span className="text-2xs text-ink-faint">
                  CycloneDX 1.6, the stored document byte for byte (ADR-0002).
                </span>
                <LinkButton href={cbomUrl(scan.id)} download={`qorbit-cbom-${short}.json`}>
                  <Download className="h-3 w-3" aria-hidden /> Download
                </LinkButton>
              </li>
              <li className="grid grid-cols-[10rem_1fr_auto] items-center gap-3 px-3 py-2">
                <span className="text-xs font-medium text-ink">PDF</span>
                <span className="text-2xs text-ink-faint">The three reports above, rendered by the server.</span>
                <span className="text-2xs text-ink-faint">above</span>
              </li>
              <li className="grid grid-cols-[10rem_1fr_auto] items-center gap-3 px-3 py-2">
                <span className="text-xs font-medium text-ink">CSV</span>
                <span className="text-2xs text-ink-faint">
                  The Inventory's stored values, one row per artefact — generated in the browser
                  from the loaded CBOM, not by a server renderer.
                </span>
                <Button
                  disabled={artefacts.length === 0}
                  onClick={() =>
                    downloadText(`qorbit-inventory-${short}.csv`, inventoryCsv(sortByRisk(artefacts)), "text/csv")
                  }
                >
                  <Download className="h-3 w-3" aria-hidden /> Download
                </Button>
              </li>
              <li
                data-testid="export-html"
                data-state="not-computed"
                className="grid grid-cols-[10rem_1fr] items-center gap-3 px-3 py-2"
              >
                <span className="text-xs font-medium text-ink-dim">HTML</span>
                <NotComputed reason="not available — ECDAT renders its reports as PDF only, and no HTML renderer exists yet" />
              </li>
            </ul>
          </Panel>
        </div>
      )}
    </div>
  );
}
