import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

import type { Band } from "@/api/types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Band colour, in one place.
 *
 * These are the ONLY saturated colours in the console. Everything else is
 * slate, so a red pixel always means the same thing and a reader can scan for
 * severity without reading a word.
 */
export const BAND_STYLE: Record<Band, { text: string; bg: string; dot: string }> = {
  Critical: {
    text: "text-critical",
    bg: "bg-critical/10 border-critical/40",
    dot: "bg-critical",
  },
  High: { text: "text-high", bg: "bg-high/10 border-high/40", dot: "bg-high" },
  Medium: {
    text: "text-medium",
    bg: "bg-medium/10 border-medium/40",
    dot: "bg-medium",
  },
  Low: { text: "text-ink-faint", bg: "bg-low/10 border-low/40", dot: "bg-low" },
};

/** `a1b2c3d4e5f6…` -> `a1b2c3d4`, for a bom-ref in a dense column. */
export function shortRef(bomRef: string, length = 8): string {
  return bomRef.slice(0, length);
}

/** `path/to/file.py:42` -> `file.py:42`, keeping the part that identifies it. */
export function shortLocator(locator: string): string {
  const parts = locator.split("/");
  return parts.length > 2 ? `…/${parts.slice(-2).join("/")}` : locator;
}

export function formatDate(iso: string | null): string {
  if (!iso) return "—";
  return iso.slice(0, 10);
}

/** `2026-09-10T06:35:35.824Z` -> `2026-09-10 06:35 UTC`. Stored times are UTC. */
export function formatDateTime(iso: string | null): string {
  if (!iso) return "—";
  return `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;
}
