/**
 * The console frame a screen's header reads (ADR-0038).
 *
 * The v2 design puts the breadcrumb, the scoring-context chips, search, the
 * status chip and the profile INSIDE each page's topline, beside its title --
 * not in a bar above it. So ScreenHeader draws them, and this is how it
 * reaches the shared scan view without every screen threading it through.
 *
 * `null` outside the console: a screen rendered on its own (as the screen
 * tests do) gets its title and actions and no frame.
 */
import { createContext, useContext } from "react";

import type { ScanView } from "@/state/inventory";

export interface ConsoleFrame {
  view: ScanView;
  /** Lands on a filtered Inventory. */
  onSearch: (query: string) => void;
}

export const ConsoleContext = createContext<ConsoleFrame | null>(null);

export function useConsole(): ConsoleFrame | null {
  return useContext(ConsoleContext);
}
