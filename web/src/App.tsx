/**
 * The ECDAT console shell, in the v2 design (ADR-0038; first matched to a
 * design in ADR-0032).
 *
 * A full-height left column (mark, grouped nav, connection, key, engine) and
 * one screen at a time from the hash route. Each screen's topline carries the
 * crumb, context chips, search, status and profile -- through ConsoleContext,
 * since the v2 design puts them beside the title, not in a bar above it. The
 * scan view is loaded ONCE here and shared, so every screen reads the same
 * document -- a Mosca rescore on the Overview is what the Inventory, Roadmap
 * and Agility screens show too.
 *
 * In front of it all sits the sign-in gate (ADR-0035): shown when the server
 * refuses the console's key -- or it has none -- and never otherwise. A new
 * sign-in remounts the console, so every screen reloads with the new key.
 */
import { useEffect, useMemo, useState, type ReactNode } from "react";

import { NewScanDialog } from "@/components/NewScanDialog";
import { SignIn } from "@/components/SignIn";
import { ConsoleContext, type ConsoleFrame } from "@/components/shell/console";
import { Sidebar, type Connection } from "@/components/shell/Sidebar";
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
import { AuthContext, useAuthState } from "@/state/auth";
import { NO_FILTERS, useScanView, type Filters } from "@/state/inventory";
import { driftMeasure } from "@/state/metrics";

export default function App() {
  const auth = useAuthState();

  if (auth.status === "required") {
    return <SignIn reason={auth.reason} onSignIn={auth.signIn} />;
  }
  if (auth.status === "checking") {
    return (
      <div role="status" className="flex h-full items-center justify-center bg-ground text-[12px] text-ink-faint">
        Checking the API key…
      </div>
    );
  }
  return (
    <AuthContext.Provider value={auth}>
      <Console key={auth.session} />
    </AuthContext.Provider>
  );
}

function Console() {
  const view = useScanView();
  const route = useRoute();
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);
  const [creating, setCreating] = useState(false);
  const frame = useMemo<ConsoleFrame>(
    () => ({
      view,
      onSearch: (q) => navigate("inventory", q ? { q } : undefined),
      onRunScan: () => setCreating(true),
    }),
    [view],
  );

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

  // The drift badge is a count only where drift could be assessed at all.
  const drift = driftMeasure(view.scan, view.artefacts);

  return (
    <div className="v2 app" data-ambient={route.route ?? "overview"}>
      <Sidebar
        current={route.route}
        connection={connection}
        view={view}
        driftCount={drift.status === "computed" ? drift.value : null}
      />
      <main className="main">
        {view.error ? (
          <div role="alert" className="alert-strip mx-6 mt-4">
            {view.error}
          </div>
        ) : null}
        <ConsoleContext.Provider value={frame}>{screen}</ConsoleContext.Provider>
      </main>
      {/* One dialog for every screen's Run scan; a stored scan becomes the loaded one. */}
      <NewScanDialog open={creating} onOpenChange={setCreating} onCreated={(scanId) => view.selectScan(scanId)} />
    </div>
  );
}
