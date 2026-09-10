/**
 * The user menu -- VISUAL ONLY (ADR-0031).
 *
 * ECDAT has no authentication yet: the API serves the whole inventory, and its
 * verified fix diffs, unauthenticated on localhost (PUNCHLIST, Tier-3). A menu
 * that offered "Sign out" would imply a session that does not exist, so every
 * entry here is disabled and the panel says why in plain text.
 */
import { useEffect, useRef, useState } from "react";

import { cn } from "@/lib/format";

export function UserMenu() {
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

  return (
    <div ref={root} className="relative">
      <button
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="User menu (cosmetic until authentication lands)"
        onClick={() => setOpen((value) => !value)}
        className={cn(
          "flex h-7 w-7 items-center justify-center border text-[10px] font-semibold tracking-wide transition-colors",
          open ? "border-ink-dim bg-raised text-ink" : "border-line text-ink-dim hover:border-ink-faint",
        )}
      >
        OP
      </button>
      {open ? (
        <div
          role="menu"
          className="absolute right-0 top-9 z-30 w-64 border border-line bg-panel shadow-2xl"
        >
          <div className="border-b border-line px-3 py-2">
            <div className="text-xs font-medium text-ink">Local operator</div>
            <div className="mt-0.5 text-2xs leading-snug text-ink-faint">
              No authentication is configured. This menu is cosmetic until the
              Tier-3 auth work lands; the API is unauthenticated on localhost.
            </div>
          </div>
          {["Profile", "Switch workspace", "Sign out"].map((item) => (
            <div
              key={item}
              role="menuitem"
              aria-disabled="true"
              className="cursor-not-allowed px-3 py-1.5 text-2xs text-ink-faint"
            >
              {item}
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}
