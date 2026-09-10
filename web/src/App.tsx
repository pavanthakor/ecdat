/**
 * The Q-orbit console shell, laid out as web/design/ has it (ADR-0032).
 *
 * A full-height left column (mark, status, grouped nav, operator), then the
 * top bar, the status strip and one screen at a time from the hash route. The
 * scan view is loaded ONCE here and shared, so every screen reads the same
 * document -- a Mosca rescore on the Overview is what the Inventory, Roadmap
 * and Agility screens show too.
 */
import { useEffect, useState, type ReactNode } from "react";

import { Sidebar, type Connection } from "@/components/shell/Sidebar";
import { StatusStrip } from "@/components/shell/StatusStrip";
import { TopBar } from "@/components/shell/TopBar";
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

export default function App() {
  const view = useScanView();
  const route = useRoute();
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);
  const [collapsed, setCollapsed] = useState(false);

  // The top-bar search arrives as `#/inventory?q=`; it seeds the table filter.
  const query = route.route === "inventory" ? route.params.get("q") : null;
  useEffect(() => {
    if (query !== null) setFilters((current) => ({ ...current, query }));
  }, [query]);

  const connection: Connection = view.error ? "error" : view.loading ? "connecting" : "connected";

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
    <div className="flex h-full bg-ground text-ink">
      <Sidebar
        current={route.route}
        collapsed={collapsed}
        onToggle={() => setCollapsed((value) => !value)}
        connection={connection}
        analysing={Boolean(view.scan) && !view.loading}
      />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar view={view} onSearch={(q) => navigate("inventory", q ? { q } : undefined)} />
        <StatusStrip view={view} />
        {view.error ? (
          <div
            role="alert"
            className="border-b border-critical/40 bg-critical/10 px-6 py-1.5 text-2xs text-critical"
          >
            {view.error}
          </div>
        ) : null}
        <main className="min-h-0 flex-1 overflow-auto">{screen}</main>
      </div>
    </div>
  );
}
