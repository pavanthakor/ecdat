/**
 * REPORTS -- the three PDFs (ADR-0020) and the offline export formats, laid out
 * as web/design/ has it (ADR-0032): three report cards, then a tile per format.
 *
 * Every report is rendered ON REQUEST from the stored CBOM by
 * `GET /scans/{id}/report/{kind}`: nothing is re-scanned, so a report cannot
 * disagree with this console for the same scan. The design tags the technical
 * report "PDF / HTML" and the coverage report "CSV"; both are PDF only, so the
 * tags here say PDF, and the HTML tile says it is not available.
 *
 * The files are fetched WITH the API key (ADR-0035) -- a plain link could not
 * send it -- so each is a button, not an `<a href>`.
 */
import { Download, ExternalLink, FileText } from "lucide-react";
import type { ReactNode } from "react";

import { cbomPath, reportPath } from "@/api/client";
import type { Artefact, ReportKind, ScanSummary } from "@/api/types";
import { FileButton } from "@/components/FileButton";
import { EmptyPanel, NotComputed } from "@/components/Honest";
import { Panel, ScreenHeader, Tag } from "@/components/Panel";
import { downloadText } from "@/lib/download";
import { inventoryCsv, sortByRisk } from "@/state/metrics";

/** One-line summaries of reports/executive.py, technical.py and coverage.py. */
const REPORTS: { kind: ReportKind; title: string; sub: string }[] = [
  {
    kind: "executive",
    title: "Executive Report",
    sub: "Two pages: the estate's shape, the five artefacts that decide the plan, the binding deadline.",
  },
  {
    kind: "technical",
    title: "Technical Report",
    sub: "Every artefact with its evidence, fired rules, score breakdown and verified fix.",
  },
  {
    kind: "coverage",
    title: "Coverage Report",
    sub: "What this scan did not look at: views, scanners, and the limits that hold for every scan.",
  },
];

function Tile({ glyph, name, sub, action }: { glyph: string; name: string; sub: string; action: ReactNode }) {
  return (
    <div className="flex min-h-[8.5rem] flex-col rounded-lg border border-line p-4">
      <span className="font-mono text-[14px] text-ink-dim">{glyph}</span>
      <span className="mt-3 text-[13px] font-semibold text-ink">{name}</span>
      <span className="mt-1 text-[11.5px] leading-snug text-ink-faint">{sub}</span>
      <div className="mt-auto pt-3">{action}</div>
    </div>
  );
}

export function ReportsScreen({ scan, artefacts }: { scan: ScanSummary | null; artefacts: Artefact[] }) {
  const short = scan?.id.slice(0, 8) ?? "";
  return (
    <div>
      <ScreenHeader
        title="Reports"
        subtitle="Prepare analyst-ready exports without masking coverage gaps. Rendered on request from the stored CBOM — nothing is re-scanned, and nothing leaves this machine."
      />
      {!scan ? (
        <div className="px-6 pb-6">
          <EmptyPanel title="No scan selected" />
        </div>
      ) : (
        <div className="space-y-4 px-6 pb-6">
          <div className="grid gap-4 md:grid-cols-3">
            {REPORTS.map((report) => (
              <section
                key={report.kind}
                data-testid={`report-${report.kind}`}
                className="rounded-lg border border-line bg-panel p-5"
              >
                <div className="flex items-start justify-between">
                  <span className="flex h-9 w-9 items-center justify-center rounded-md border border-line text-ink-dim">
                    <FileText className="h-4 w-4" aria-hidden />
                  </span>
                  <Tag>PDF</Tag>
                </div>
                <h2 className="mt-4 text-[16px] font-semibold text-ink">{report.title}</h2>
                <p className="mt-1.5 min-h-[2.5rem] text-[12px] leading-relaxed text-ink-faint">{report.sub}</p>
                <div className="mt-4 flex items-center gap-2">
                  <FileButton
                    mode="view"
                    path={reportPath(scan.id, report.kind)}
                    filename={`ecdat-${report.kind}-${short}.pdf`}
                  >
                    <ExternalLink className="h-3.5 w-3.5" aria-hidden /> View
                  </FileButton>
                  <FileButton
                    variant="quiet"
                    path={reportPath(scan.id, report.kind)}
                    filename={`ecdat-${report.kind}-${short}.pdf`}
                  >
                    Generate
                  </FileButton>
                </div>
              </section>
            ))}
          </div>

          <Panel
            eyebrow="Offline export formats"
            title="Available artifacts"
            meta={
              <span className="font-mono text-[10px] uppercase tracking-wider">
                Generated locally · nothing leaves this machine
              </span>
            }
          >
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              <Tile
                glyph="{ }"
                name="CBOM JSON"
                sub="Machine-readable CycloneDX 1.6 — the stored document, byte for byte"
                action={
                  <FileButton
                    bare
                    path={cbomPath(scan.id)}
                    filename={`ecdat-cbom-${short}.json`}
                    label="Download CBOM JSON"
                    className="inline-flex text-ink-dim transition-colors hover:text-ink"
                  >
                    <Download className="h-4 w-4" aria-hidden />
                  </FileButton>
                }
              />
              <Tile
                glyph="PDF"
                name="PDF"
                sub="Executive / technical / coverage — rendered by the server, above"
                action={<span className="text-[11px] text-ink-faint">see the report cards</span>}
              />
              <div
                data-testid="export-html"
                data-state="not-computed"
                className="flex min-h-[8.5rem] flex-col rounded-lg border border-dashed border-line p-4"
              >
                <span className="font-mono text-[14px] text-ink-faint">&lt;/&gt;</span>
                <span className="mt-3 text-[13px] font-semibold text-ink-dim">HTML</span>
                <NotComputed
                  reason="not available — ECDAT renders its reports as PDF only, and no HTML renderer exists yet"
                  className="mt-1"
                />
              </div>
              <Tile
                glyph="CSV"
                name="CSV"
                sub="Inventory extract — generated in the browser from the stored CBOM"
                action={
                  <button
                    type="button"
                    aria-label="Download inventory CSV"
                    disabled={artefacts.length === 0}
                    onClick={() =>
                      downloadText(`ecdat-inventory-${short}.csv`, inventoryCsv(sortByRisk(artefacts)), "text/csv")
                    }
                    className="inline-flex text-ink-dim transition-colors hover:text-ink disabled:opacity-40"
                  >
                    <Download className="h-4 w-4" aria-hidden />
                  </button>
                }
              />
            </div>
          </Panel>
        </div>
      )}
    </div>
  );
}
