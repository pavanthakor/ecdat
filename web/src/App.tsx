/**
 * The Q-orbit console shell (ADR-0031).
 *
 * Top bar (which estate, which scan, ready or not), a grouped left nav, and
 * one screen at a time from the hash route. The scan view is loaded ONCE here
 * and shared, so every screen reads the same document -- and a Mosca rescore
 * on the Overview is what the Inventory, Roadmap and Agility screens show too.
 */
import { useEffect, useMemo, useState, type ReactNode } from "react";

import { Sidebar } from "@/components/shell/Sidebar";
import { TopBar } from "@/components/shell/TopBar";
import { formatDate } from "@/lib/format";
import { navigate, useRoute } from "@/lib/router";
import { AgilityScreen } from "@/screens/Agility";
import { CompareScreen } from "@/screens/Compare";
import { CoverageScreen } from "@/screens/Coverage";
import { DriftScreen } from "@/screens/Drift";
import { FixesScreen } from "@/screens/Fixes";
import { InventoryScreen } from "@/screens/Inventory";
import { NotFoundScreen } from "@/screens/NotFound";
import { OverviewScreen } from "@/screens/Overview";
import { ReportsScreen } from "@/screens/Reports";
import { RiskAnalysisScreen } from "@/screens/RiskAnalysis";
import { RoadmapScreen } from "@/screens/Roadmap";
import { ScansScreen } from "@/screens/Scans";
import { SettingsScreen } from "@/screens/Settings";
import { NO_FILTERS, useScanView, type Filters } from "@/state/inventory";
import { engineLine } from "@/state/presentation";

export default function App() {
  const view = useScanView();
  const route = useRoute();
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);

  // The top-bar search arrives as `#/inventory?q=`; it seeds the table filter.
  const query = route.route === "inventory" ? route.params.get("q") : null;
  useEffect(() => {
    if (query !== null) setFilters((current) => ({ ...current, query }));
  }, [query]);

  const footer = useMemo(
    () => (view.scan ? engineLine(view.scan, view.artefacts) : null),
    [view.scan, view.artefacts],
  );

  let screen: ReactNode;
  switch (route.route) {
    case "overview":
      screen = <OverviewScreen view={view} />;
      break;
    case "scans":
      screen = <ScansScreen view={view} />;
      break;
    case "inventory":
      screen = (
        <InventoryScreen
          view={view}
          filters={filters}
          onFilters={setFilters}
          selectedRef={route.params.get("ref")}
        />
      );
      break;
    case "risk":
      screen = <RiskAnalysisScreen scan={view.scan} />;
      break;
    case "drift":
      screen = <DriftScreen artefacts={view.artefacts} scan={view.scan} loading={view.loading} />;
      break;
    case "roadmap":
      screen = <RoadmapScreen artefacts={view.artefacts} scan={view.scan} />;
      break;
    case "fixes":
      screen = <FixesScreen scan={view.scan} />;
      break;
    case "agility":
      screen = <AgilityScreen artefacts={view.artefacts} loading={view.loading} />;
      break;
    case "coverage":
      screen = <CoverageScreen scan={view.scan} artefacts={view.artefacts} />;
      break;
    case "reports":
      screen = <ReportsScreen scan={view.scan} artefacts={view.artefacts} />;
      break;
    case "compare":
      screen = <CompareScreen scans={view.scans} current={view.scan} />;
      break;
    case "settings":
      screen = <SettingsScreen scan={view.scan} artefacts={view.artefacts} />;
      break;
    default:
      screen = <NotFoundScreen path={route.path} />;
  }

  return (
    <div className="flex h-full flex-col bg-ground text-ink">
      <TopBar view={view} onSearch={(q) => navigate("inventory", q ? { q } : undefined)} />

      {view.error ? (
        <div
          role="alert"
          className="border-b border-critical/40 bg-critical/10 px-4 py-1.5 text-2xs text-critical"
        >
          {view.error}
        </div>
      ) : null}

      <div className="flex min-h-0 flex-1">
        <Sidebar current={route.route} />
        <div className="flex min-w-0 flex-1 flex-col">
          <main className="min-h-0 flex-1 overflow-auto">{screen}</main>
          {/* Quiet, auditable: what produced this view. */}
          <footer className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-line bg-panel px-4 py-1.5 text-[10px] text-ink-faint">
            {view.scan ? (
              <>
                <span className="font-mono">scanned {formatDate(view.scan.created_at)}</span>
                {footer?.parts.map((part) => (
                  <span key={part} className="font-mono before:mr-3 before:content-['·']">
                    {part}
                  </span>
                ))}
                {footer?.warning ? (
                  <span className="text-high" title={footer.warning}>
                    · engine mismatch
                  </span>
                ) : null}
              </>
            ) : (
              <span>no scan loaded</span>
            )}
          </footer>
        </div>
      </div>
    </div>
  );
}
