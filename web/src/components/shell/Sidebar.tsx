/**
 * The left column, as the v2 mockups draw it (ADR-0038): the ECDAT mark, the
 * nav grouped ANALYZE / PLAN / REPORT with Settings after them, and a foot
 * with the connection, the key in use and the engine that produced this view.
 *
 * Links are real `#/` hrefs, so middle-click and copy-link work; a plain click
 * navigates in place. The active entry is the elevated row with a white bar
 * and `aria-current="page"`. Two mockup details are NOT copied, because
 * colour means severity and nothing else (ADR-0031): the drift badge is a
 * neutral count, not a red one, and "System Operational" is a neutral dot
 * that says what is actually known -- whether the API answered.
 *
 * The foot carries what ADR-0032's status strip did: engine versions from
 * `engine_versions`, a mismatch if there was one, and the scan's id and age.
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
import { useMemo, type MouseEvent } from "react";

import { cn, relativeAge } from "@/lib/format";
import { ROUTES, hrefFor, navigate, type RouteDef, type RouteGroup, type RouteId } from "@/lib/router";
import { useAuth } from "@/state/auth";
import type { ScanView } from "@/state/inventory";
import { engineLine } from "@/state/presentation";

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

const GROUPS: { id: RouteGroup; label: string | null }[] = [
  { id: "analyze", label: "Analyze" },
  { id: "plan", label: "Plan" },
  { id: "report", label: "Report" },
  { id: "settings", label: null },
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

function NavItem({ route, active, badge }: { route: RouteDef; active: boolean; badge: number | null }) {
  const Icon = ICONS[route.id];
  return (
    <li>
      <a
        href={hrefFor(route.id)}
        aria-label={route.title}
        aria-current={active ? "page" : undefined}
        onClick={(event) => follow(event, route.id)}
        className={cn("nav-item", active && "active")}
      >
        <Icon className="h-[15px] w-[15px]" aria-hidden />
        <span className="min-w-0 flex-1 truncate">{route.title}</span>
        {badge ? (
          <span className="nav-badge" title={`${badge} drift finding(s) on this scan`}>
            {badge}
          </span>
        ) : null}
      </a>
    </li>
  );
}

export function Sidebar({
  current,
  connection,
  view,
  driftCount,
}: {
  current: RouteId | null;
  connection: Connection;
  view: ScanView;
  /** Drift findings on the scan, when drift could be assessed at all. */
  driftCount: number | null;
}) {
  const { principal } = useAuth();
  const scan = view.scan;
  const engine = useMemo(() => (scan ? engineLine(scan, view.artefacts) : null), [scan, view.artefacts]);

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-row">
          <span className="brand-mark" aria-hidden>
            E
          </span>
          <span className="brand-name">ECDAT</span>
        </div>
        <div className="brand-sub">CRYPTOGRAPHIC SECURITY CONSOLE</div>
      </div>

      <nav aria-label="Primary" className="flex flex-col gap-6">
        {GROUPS.map((group) => (
          <div key={group.id}>
            {group.label ? <div className="nav-label">{group.label}</div> : null}
            <ul className="nav-group">
              {ROUTES.filter((route) => route.group === group.id).map((route) => (
                <NavItem
                  key={route.id}
                  route={route}
                  active={current === route.id}
                  badge={route.id === "drift" ? driftCount : null}
                />
              ))}
            </ul>
          </div>
        ))}
      </nav>

      <div className="sidebar-foot">
        <div className="system-status" data-connection={connection}>
          <span
            className={cn("dot", connection === "error" && "error", connection === "connecting" && "busy")}
            aria-hidden
          />
          {CONNECTION_LABEL[connection]}
        </div>
        <div className="analyst-row">
          <span className="avatar" aria-hidden>
            {(principal?.name ?? "?").slice(0, 2).toUpperCase()}
          </span>
          <div className="min-w-0">
            <div className="analyst-name truncate">{principal?.name ?? "API key"}</div>
            <div className="analyst-role">{principal ? `${principal.role} key` : "role unknown"}</div>
          </div>
        </div>
        <div className="engine-ver">
          {engine?.parts.map((part) => (
            <div key={part} className="truncate" title={part}>
              {part}
            </div>
          ))}
          {engine?.warning ? (
            <div className="font-bold text-ink-dim" title={engine.warning}>
              engine mismatch
            </div>
          ) : null}
          {scan ? (
            <div className="truncate" title={scan.created_at}>
              Scan {scan.id.slice(0, 8)} · {relativeAge(scan.created_at)}
            </div>
          ) : null}
        </div>
      </div>
    </aside>
  );
}
