/**
 * The left nav, grouped the way an analyst works: ANALYZE what is there, PLAN
 * the move, REPORT on it. Settings sits apart at the foot.
 *
 * Links are real `#/` hrefs, so middle-click and copy-link work; a plain click
 * navigates in place. The active entry carries `aria-current="page"` and a
 * slate edge -- the same edge-marker language as a severity row, in slate,
 * because selection is not severity.
 */
import type { LucideIcon } from "lucide-react";
import {
  CalendarRange,
  Diff,
  FileCheck2,
  FileText,
  GitCompareArrows,
  LayoutDashboard,
  Radar,
  ScanLine,
  Settings,
  ShieldAlert,
  Table2,
  Workflow,
} from "lucide-react";
import type { MouseEvent } from "react";

import { cn } from "@/lib/format";
import { ROUTES, hrefFor, navigate, type RouteDef, type RouteGroup, type RouteId } from "@/lib/router";

const ICONS: Record<RouteId, LucideIcon> = {
  overview: LayoutDashboard,
  scans: ScanLine,
  inventory: Table2,
  risk: ShieldAlert,
  drift: GitCompareArrows,
  roadmap: CalendarRange,
  fixes: FileCheck2,
  agility: Workflow,
  coverage: Radar,
  reports: FileText,
  compare: Diff,
  settings: Settings,
};

const GROUPS: { id: RouteGroup; label: string }[] = [
  { id: "analyze", label: "Analyze" },
  { id: "plan", label: "Plan" },
  { id: "report", label: "Report" },
];

function follow(event: MouseEvent<HTMLAnchorElement>, id: RouteId) {
  if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey) return;
  event.preventDefault();
  navigate(id);
}

function NavItem({ route, active }: { route: RouteDef; active: boolean }) {
  const Icon = ICONS[route.id];
  return (
    <li>
      <a
        href={hrefFor(route.id)}
        aria-label={route.title}
        aria-current={active ? "page" : undefined}
        onClick={(event) => follow(event, route.id)}
        className={cn(
          "flex items-center gap-2.5 border-l-2 px-4 py-1.5 text-xs transition-colors",
          active
            ? "border-ink-dim bg-raised font-medium text-ink"
            : "border-transparent text-ink-dim hover:bg-raised/50 hover:text-ink",
        )}
      >
        <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden />
        <span className="truncate">{route.title}</span>
      </a>
    </li>
  );
}

export function Sidebar({ current }: { current: RouteId | null }) {
  return (
    <nav
      aria-label="Primary"
      className="flex w-52 shrink-0 flex-col border-r border-line bg-panel"
    >
      <div className="flex-1 overflow-y-auto py-3">
        {GROUPS.map((group) => (
          <div key={group.id} className="mb-4">
            <div className="px-4 pb-1.5 text-[10px] font-medium uppercase tracking-[0.2em] text-ink-faint">
              {group.label}
            </div>
            <ul>
              {ROUTES.filter((route) => route.group === group.id).map((route) => (
                <NavItem key={route.id} route={route} active={current === route.id} />
              ))}
            </ul>
          </div>
        ))}
      </div>
      <ul className="border-t border-line py-2">
        {ROUTES.filter((route) => route.group === "settings").map((route) => (
          <NavItem key={route.id} route={route} active={current === route.id} />
        ))}
      </ul>
    </nav>
  );
}
