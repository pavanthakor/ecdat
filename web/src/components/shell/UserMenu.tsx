/**
 * The user menu: WHICH KEY the console holds, and its role (ADR-0035).
 *
 * ECDAT has no user accounts. A key is issued to a name with `ecdat api-key
 * create`, and that name is what shows here. "Sign out" forgets the key in
 * this browser; the key stays valid until it is revoked on the server. The
 * design's Profile and Switch-workspace entries stay disabled, and say why:
 * there are no profiles or workspaces to switch between.
 */
import { ChevronDown, LogOut } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { cn } from "@/lib/format";
import { useAuth } from "@/state/auth";

export function UserMenu() {
  const { principal, signOut } = useAuth();
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const close = (event: MouseEvent | KeyboardEvent) => {
      if (event instanceof KeyboardEvent ? event.key === "Escape" : !root.current?.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", close);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", close);
    };
  }, [open]);

  const name = principal?.name ?? "API key";
  const role = principal?.role ?? "role unknown";
  const initials = (principal?.name ?? "?").slice(0, 2).toUpperCase();

  return (
    <div ref={root} className="relative">
      <button
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="User menu"
        onClick={() => setOpen((value) => !value)}
        className={cn(
          "flex items-center gap-2.5 rounded-md border px-2 py-1.5 transition-colors",
          open ? "border-ink-dim bg-raised" : "border-line hover:border-ink-faint",
        )}
      >
        <span className="flex h-7 w-7 items-center justify-center rounded-full border border-ink-faint text-[10px] font-semibold text-ink">
          {initials}
        </span>
        <span className="hidden text-left leading-tight xl:block">
          <span className="block text-[12px] font-medium text-ink">{name}</span>
          <span className="block text-[9.5px] uppercase tracking-wider text-ink-faint">{role}</span>
        </span>
        <ChevronDown className="h-3.5 w-3.5 text-ink-faint" aria-hidden />
      </button>
      {open ? (
        <div role="menu" className="absolute right-0 top-11 z-30 w-64 rounded-lg border border-line bg-panel shadow-2xl">
          <div className="border-b border-line px-3 py-2.5">
            <div className="text-[12.5px] font-medium text-ink">
              {name} · {role}
            </div>
            <div className="mt-0.5 text-[11px] leading-snug text-ink-faint">
              An API key issued on the server. A viewer reads; an admin also runs scans and fix passes.
            </div>
          </div>
          {["Profile", "Switch workspace"].map((item) => (
            <div
              key={item}
              role="menuitem"
              aria-disabled="true"
              title="ECDAT has keys, not accounts: there is nothing to switch to"
              className="cursor-not-allowed px-3 py-1.5 text-[12px] text-ink-faint"
            >
              {item}
            </div>
          ))}
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              setOpen(false);
              signOut();
            }}
            title="Forget the key in this browser. It stays valid until revoked on the server."
            className="flex w-full items-center gap-2 border-t border-line px-3 py-2 text-left text-[12px] text-ink hover:bg-raised"
          >
            <LogOut className="h-3.5 w-3.5" aria-hidden /> Sign out
          </button>
        </div>
      ) : null}
    </div>
  );
}
