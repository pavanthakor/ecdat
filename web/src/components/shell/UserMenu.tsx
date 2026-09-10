/**
 * The user menu -- VISUAL ONLY (ADR-0031).
 *
 * ECDAT has no authentication yet: the API serves the whole inventory, and its
 * verified fix diffs, unauthenticated on localhost (PUNCHLIST, Tier-3). The
 * trigger has the design's shape -- round avatar, name, role, chevron -- and
 * every entry in the menu is disabled, with a sentence saying why.
 */
import { ChevronDown } from "lucide-react";
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
          "flex items-center gap-2.5 rounded-md border px-2 py-1.5 transition-colors",
          open ? "border-ink-dim bg-raised" : "border-line hover:border-ink-faint",
        )}
      >
        <span className="flex h-7 w-7 items-center justify-center rounded-full border border-ink-faint text-[10px] font-semibold text-ink">
          OP
        </span>
        <span className="hidden text-left leading-tight xl:block">
          <span className="block text-[12px] font-medium text-ink">Local operator</span>
          <span className="block text-[9.5px] uppercase tracking-wider text-ink-faint">No auth · cosmetic</span>
        </span>
        <ChevronDown className="h-3.5 w-3.5 text-ink-faint" aria-hidden />
      </button>
      {open ? (
        <div
          role="menu"
          className="absolute right-0 top-11 z-30 w-64 rounded-lg border border-line bg-panel shadow-2xl"
        >
          <div className="border-b border-line px-3 py-2.5">
            <div className="text-[12.5px] font-medium text-ink">Local operator</div>
            <div className="mt-0.5 text-[11px] leading-snug text-ink-faint">
              No authentication is configured. This menu is cosmetic until the
              Tier-3 auth work lands; the API is unauthenticated on localhost.
            </div>
          </div>
          {["Profile", "Switch workspace", "Sign out"].map((item) => (
            <div
              key={item}
              role="menuitem"
              aria-disabled="true"
              className="cursor-not-allowed px-3 py-1.5 text-[12px] text-ink-faint"
            >
              {item}
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}
