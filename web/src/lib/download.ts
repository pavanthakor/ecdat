/**
 * Save or show a file the browser holds -- a CSV projection of the stored
 * CBOM, a compare response, or a PDF fetched with the key. Local only: a Blob
 * URL, no further request.
 */
export function downloadBlob(filename: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export function downloadText(filename: string, text: string, type: string): void {
  downloadBlob(filename, new Blob([text], { type }));
}

/**
 * Show a Blob in a tab that was opened BEFORE the fetch -- a tab opened after
 * an `await` is no longer a user gesture, and a popup blocker would eat it.
 * With no tab to show it in, the file is saved instead.
 */
export function showBlob(tab: Window | null, filename: string, blob: Blob): void {
  if (!tab) {
    downloadBlob(filename, blob);
    return;
  }
  const url = URL.createObjectURL(blob);
  tab.location.href = url;
  // The tab needs the URL while it loads; a minute is ample, then free it.
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}
