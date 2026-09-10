/**
 * Save text the browser generated -- a CSV projection of the stored CBOM, or a
 * compare response -- as a file. Local only: a Blob URL, no request.
 */
export function downloadText(filename: string, text: string, type: string): void {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}
