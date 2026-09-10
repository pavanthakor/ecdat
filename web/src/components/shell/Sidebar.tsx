/**
 * The left column, as the design has it: the Q-orbit mark and a collapse
 * control, a connection status box, the nav grouped ANALYZE / PLAN / REPORT,
 * Settings pinned at the foot, and the (cosmetic) operator block.
 *
 * Links are real `#/` hrefs, so middle-click and copy-link work; a plain click
 * navigates in place. The active entry is a bordered box with a chevron and
 * `aria-current="page"` -- in slate, because selection is not severity and the
 * colour lock keeps orange in the logo (ADR-0032).
 */
import type { LucideIcon } from "lucide-react";
import {
  Activity,
  CalendarRange,
  ChevronRight,
  Diff,
  FileCheck2,
  FileText,
  GitCompareArrows,
  LayoutDashboard,
  PanelLeft,
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
import { QOrbitLogo, QOrbitMark } from "./Logo";

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

export type Connection = "connected" | "connecting" | "error";

const CONNECTION_LABEL: Record<Connection, string> = {
  connected: "API connected",
  connecting: "Connecting",
  error: "Request failed",
};

function follow(event: MouseEvent<HTMLAnchorElement>, id: RouteId) {
  if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey) return;
  event.preventDefault();
  navigate(id);
}

function NavItem({
  route,
  active,
  collapsed,
}: {
  route: RouteDef;
  active: boolean;
  collapsed: boolean;
}) {
  const Icon = ICONS[route.id];
  return (
    <li>
      <a
        href={hrefFor(route.id)}
        aria-label={route.title}
        title={collapsed ? route.title : undefined}
        aria-current={active ? "page" : undefined}
        onClick={(event) => follow(event, route.id)}
        className={cn(
          "flex items-center gap-3 rounded-md border px-3 py-2 text-[13px] transition-colors",
          collapsed && "justify-center px-0",
          active
            ? "border-ink-faint/70 bg-raised font-medium text-ink"
            : "border-transparent text-ink-dim hover:bg-raised/60 hover:text-ink",
        )}
      >
        <Icon className="h-4 w-4 shrink-0" aria-hidden />
        {collapsed ? null : (
          <>
            <span className="min-w-0 flex-1 truncate">{route.title}</span>
            {active ? <ChevronRight className="h-3.5 w-3.5 shrink-0 text-ink-dim" aria-hidden /> : null}
          </>
        )}
      </a>
    </li>
  );
}

export function Sidebar({
  current,
  collapsed,
  onToggle,
  connection,
  analysing,
}: {
  current: RouteId | null;
  collapsed: boolean;
  onToggle: () => void;
  connection: Connection;
  /** True when an analysis is loaded -- the mark is amber, else slate. */
  analysing: boolean;
}) {
  return (
    <aside
      className={cn(
        "flex h-full shrink-0 flex-col border-r border-line bg-ground",
        collapsed ? "w-[4.5rem]" : "w-60",
      )}
    >
      <div
        className={cn(
          "flex h-16 shrink-0 items-center border-b border-line px-4",
          collapsed ? "justify-center" : "justify-between",
        )}
      >
        {collapsed ? null : <QOrbitLogo tone={analysing ? "brand" : "muted"} />}
        <button
          type="button"
          onClick={onToggle}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          className="rounded-md p-1 text-ink-faint transition-colors hover:text-ink"
        >
          {collapsed ? (
            <QOrbitMark tone={analysing ? "brand" : "muted"} className="h-7 w-7" title="Expand sidebar" />
          ) : (
            <PanelLeft className="h-4 w-4" aria-hidden />
          )}
        </button>
      </div>

      <div className="px-3 pt-3">
        <div
          title={CONNECTION_LABEL[connection]}
          className={cn(
            "flex items-center justify-between gap-2 rounded-md border px-3 py-2",
            connection === "error" ? "border-critical/50" : "border-line",
            collapsed && "justify-center px-0",
          )}
        >
          <span className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-wider text-ink-dim">
            <span
              className={cn(
                "h-1.5 w-1.5 rounded-full",
                connection === "connected" && "bg-ink-dim",
                connection === "connecting" && "animate-pulse bg-ink-faint",
                connection === "error" && "bg-critical",
              )}
              aria-hidden
            />
            {collapsed ? null : CONNECTION_LABEL[connection]}
          </span>
          {collapsed ? null : <Activity className="h-3.5 w-3.5 text-ink-faint" aria-hidden />}
        </div>
      </div>

      <nav aria-label="Primary" className="flex min-h-0 flex-1 flex-col">
        <div className="min-h-0 flex-1 overflow-y-auto px-3 pb-3">
          {GROUPS.map((group) => (
            <div key={group.id}>
              <div
                className={cn(
                  "px-3 pb-2 pt-5 text-[10px] font-semibold uppercase tracking-[0.18em] text-ink-faint",
                  collapsed && "px-0 text-center",
                )}
              >
                {collapsed ? "·" : group.label}
              </div>
              <ul className="space-y-0.5">
                {ROUTES.filter((route) => route.group === group.id).map((route) => (
                  <NavItem key={route.id} route={route} active={current === route.id} collapsed={collapsed} />
                ))}
              </ul>
            </div>
          ))}
        </div>
        <ul className="border-t border-line px-3 py-2">
          {ROUTES.filter((route) => route.group === "settings").map((route) => (
            <NavItem key={route.id} route={route} active={current === route.id} collapsed={collapsed} />
          ))}
        </ul>
      </nav>

      <div
        className={cn("flex items-center gap-2.5 border-t border-line px-4 py-3", collapsed && "justify-center px-0")}
        title="Cosmetic until authentication lands"
      >
        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-ink-faint text-[10px] font-semibold text-ink">
          OP
        </span>
        {collapsed ? null : (
          <span className="min-w-0 leading-tight">
            <span className="block truncate text-[12.5px] font-medium text-ink">Local operator</span>
            <span className="block truncate text-[10.5px] text-ink-faint">No authentication</span>
          </span>
        )}
      </div>
    </aside>
  );
}
