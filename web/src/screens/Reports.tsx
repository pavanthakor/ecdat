/**
 * REPORTS -- the three PDFs (ADR-0020) and the offline export formats, rebuilt
 * on the v2 mockup (reports.html; ADR-0039): three report cards, then
 * "Available artifacts".
 *
 * Every report is rendered ON REQUEST from the stored CBOM by
 * `GET /scans/{id}/report/{kind}`: nothing is re-scanned, so a report cannot
 * disagree with this console for the same scan. The mockup tags the technical
 * report "PDF / HTML" and the coverage report "CSV"; all three are PDF only, so
 * the tags here say PDF, and the HTML row says it is not available.
 *
 * The files are fetched WITH the API key (ADR-0035) -- a plain link could not
 * send it -- so each is a button, not an `<a href>`. View opens the PDF in a
 * tab; Generate renders and saves it.
 */
import { Download, ExternalLink, FileCode, FileJson, FileSpreadsheet, FileText } from "lucide-react";
import type { ReactNode } from "react";

import { cbomPath, reportPath } from "@/api/client";
import type { Artefact, ReportKind, ScanSummary } from "@/api/types";
import { FileButton } from "@/components/FileButton";
import { NotComputed } from "@/components/Honest";
import { ScreenHeader } from "@/components/Panel";
import { EmptyState, PanelHead } from "@/components/v2";
import { downloadText } from "@/lib/download";
import { cn } from "@/lib/format";
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

function ArtifactRow({
  testId,
  icon,
  name,
  note,
  action,
  unavailable = false,
}: {
  testId: string;
  icon: ReactNode;
  name: string;
  note: ReactNode;
  action: ReactNode;
  unavailable?: boolean;
}) {
  return (
    <div
      data-testid={testId}
      data-state={unavailable ? "not-computed" : undefined}
      className={cn("artifact-row", unavailable && "unavailable")}
    >
      <div className="artifact-icon">{icon}</div>
      <div className="min-w-0 flex-1">
        <div className={cn("artifact-name", unavailable && "text-ink-dim")}>{name}</div>
        <div className="artifact-note">{note}</div>
      </div>
      {action}
    </div>
  );
}

export function ReportsScreen({ scan, artefacts }: { scan: ScanSummary | null; artefacts: Artefact[] }) {
  const short = scan?.id.slice(0, 8) ?? "";
  const icon = "h-4 w-4";
  return (
    <div className="content">
      <ScreenHeader
        title="Reports"
        subtitle="Prepare analyst-ready exports without masking coverage gaps. Rendered on request from the stored CBOM — nothing is re-scanned, and nothing leaves this machine."
      />
      {!scan ? (
        <EmptyState title="No scan selected" />
      ) : (
        <>
          <div className="grid-row in grid-cols-1 lg:grid-cols-3" style={{ animationDelay: "0.04s" }}>
            {REPORTS.map((report) => (
              <section key={report.kind} data-testid={`report-${report.kind}`} className="report-card">
                <div className="report-icon">
                  <FileText className={icon} aria-hidden />
                </div>
                <div className="report-title">{report.title}</div>
                <div className="report-desc">{report.sub}</div>
                <div className="report-formats">
                  <span className="format-tag">PDF</span>
                  <span className="ml-auto flex flex-wrap gap-2">
                    <FileButton
                      bare
                      mode="view"
                      className="btn-ghost"
                      title="Open the PDF in a new tab"
                      path={reportPath(scan.id, report.kind)}
                      filename={`ecdat-${report.kind}-${short}.pdf`}
                    >
                      <ExternalLink className="h-3.5 w-3.5" aria-hidden /> View
                    </FileButton>
                    <FileButton
                      bare
                      className="btn-primary"
                      title="Render and save the PDF"
                      path={reportPath(scan.id, report.kind)}
                      filename={`ecdat-${report.kind}-${short}.pdf`}
                    >
                      Generate
                    </FileButton>
                  </span>
                </div>
              </section>
            ))}
          </div>

          <section className="panel in" style={{ animationDelay: "0.1s" }}>
            <PanelHead
              title="Available artifacts"
              sub="Machine-readable and portable exports from this scan · generated locally, nothing leaves this machine"
            />
            <ArtifactRow
              testId="artifact-cbom"
              icon={<FileJson className={icon} aria-hidden />}
              name="CBOM JSON"
              note="Machine-readable CycloneDX 1.6 — the stored document, byte for byte"
              action={
                <FileButton
                  bare
                  className="btn-ghost"
                  label="Download CBOM JSON"
                  path={cbomPath(scan.id)}
                  filename={`ecdat-cbom-${short}.json`}
                >
                  <Download className="h-3.5 w-3.5" aria-hidden /> Download
                </FileButton>
              }
            />
            <ArtifactRow
              testId="artifact-pdf"
              icon={<FileText className={icon} aria-hidden />}
              name="PDF"
              note="Executive and technical variants, rendered by the server (the coverage statement is on its card above)"
              action={
                <span className="flex flex-wrap gap-2">
                  <FileButton
                    bare
                    className="btn-ghost"
                    label="Download executive PDF"
                    path={reportPath(scan.id, "executive")}
                    filename={`ecdat-executive-${short}.pdf`}
                  >
                    Executive
                  </FileButton>
                  <FileButton
                    bare
                    className="btn-ghost"
                    label="Download technical PDF"
                    path={reportPath(scan.id, "technical")}
                    filename={`ecdat-technical-${short}.pdf`}
                  >
                    Technical
                  </FileButton>
                </span>
              }
            />
            <ArtifactRow
              testId="export-html"
              unavailable
              icon={<FileCode className={icon} aria-hidden />}
              name="HTML"
              note={
                <NotComputed reason="not available — ECDAT renders its reports as PDF only, and no HTML renderer exists yet" />
              }
              action={null}
            />
            <ArtifactRow
              testId="artifact-csv"
              icon={<FileSpreadsheet className={icon} aria-hidden />}
              name="CSV"
              note="Full inventory extract — generated in the browser from the stored CBOM"
              action={
                <button
                  type="button"
                  className="btn-ghost"
                  aria-label="Download inventory CSV"
                  disabled={artefacts.length === 0}
                  onClick={() =>
                    downloadText(`ecdat-inventory-${short}.csv`, inventoryCsv(sortByRisk(artefacts)), "text/csv")
                  }
                >
                  <Download className="h-3.5 w-3.5" aria-hidden /> Download
                </button>
              }
            />
          </section>
        </>
      )}
    </div>
  );
}
