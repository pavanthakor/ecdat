/**
 * The colour audit (ADR-0031, ADR-0038, ADR-0039): colour means severity and
 * nothing else.
 *
 * Walks a rendered tree. Every element painted in a band colour -- by a
 * Tailwind band token (`text-critical`, `bg-high/10`, ...) or a v2 band class
 * (`badge-medium`, `band-bg-low`, `band-border-high`, ...) -- must name that
 * band in `data-band`, and no band colour may be set inline, where nothing
 * could check it. `coloured` lets a test assert the walk was not vacuous.
 */
export const BAND_CLASS =
  /^(?:text|bg|border|fill|stroke|badge|band-bg|band-fg|band-stroke|band-border)-(critical|high|medium|low)(?:\/\d+)?$/;
const BAND_INLINE = /var\(--(?:critical|high|medium|low)\)|#ef4444|#f59e0b|#eab308/i;

export interface ColourAudit {
  coloured: number;
  violations: string[];
}

export function auditColour(root: ParentNode = document.body): ColourAudit {
  const violations: string[] = [];
  let coloured = 0;
  for (const el of Array.from(root.querySelectorAll("*"))) {
    const snippet = el.outerHTML.slice(0, 140);
    const inline = ["style", "fill", "stroke", "color"].map((name) => el.getAttribute(name) ?? "").join(" ");
    if (BAND_INLINE.test(inline)) violations.push(`inline band colour: ${snippet}`);
    const band = Array.from(el.classList)
      .map((token) => BAND_CLASS.exec(token)?.[1])
      .find(Boolean);
    if (!band) continue;
    coloured += 1;
    if (el.getAttribute("data-band")?.toLowerCase() !== band) {
      violations.push(`${band} colour without data-band="${band}": ${snippet}`);
    }
  }
  return { coloured, violations };
}
