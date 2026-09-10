/**
 * A button for a file the API serves -- a PDF report, the stored CBOM.
 *
 * Not an `<a href>`: since ADR-0035 every API request carries the key in a
 * header, and a link cannot send one. This fetches WITH the key, then saves
 * the file or shows it in a tab. A failure is shown on the button -- in its
 * label and its title -- rather than swallowed into a dead click.
 */
import { useState, type ReactNode } from "react";

import { fetchBlob } from "@/api/client";
import { downloadBlob, showBlob } from "@/lib/download";
import { Button } from "./Panel";

type Variant = "default" | "primary" | "quiet";

export function FileButton({
  path,
  filename,
  mode = "download",
  variant,
  bare = false,
  className,
  title,
  label,
  children,
}: {
  /** The API path, e.g. `reportPath(id, "executive")`. */
  path: string;
  filename: string;
  /** `view` opens the file in a new tab; `download` saves it. */
  mode?: "download" | "view";
  variant?: Variant;
  /** A plain button (icon-sized), rather than the console's button chrome. */
  bare?: boolean;
  className?: string;
  title?: string;
  /** The accessible name, when the children are only an icon. */
  label?: string;
  children: ReactNode;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    // Opened NOW, inside the click, so a popup blocker allows it.
    const tab = mode === "view" ? window.open("", "_blank") : null;
    setBusy(true);
    try {
      const blob = await fetchBlob(path);
      if (mode === "view") showBlob(tab, filename, blob);
      else downloadBlob(filename, blob);
      setError(null);
    } catch (cause) {
      tab?.close();
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }

  const common = {
    onClick: run,
    disabled: busy,
    "aria-label": label,
    title: error ?? title,
    "data-state": error ? "error" : busy ? "busy" : "idle",
  } as const;
  const failed = error ? <span className="text-critical"> · failed</span> : null;

  if (bare) {
    return (
      <button type="button" {...common} className={className}>
        {children}
        {failed}
      </button>
    );
  }
  return (
    <Button variant={variant} className={className} {...common}>
      {children}
      {failed}
    </Button>
  );
}
