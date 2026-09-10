/**
 * Loading placeholders.
 *
 * Rows rather than a spinner, and never a flash of empty: the table keeps its
 * shape while a scan or a rescore is in flight, so the page does not collapse
 * and re-expand under the reader's cursor. Widths vary per column so the
 * placeholder reads as a table rather than a progress bar.
 */
import { cn } from "@/lib/format";

const WIDTHS = ["w-40", "w-14", "w-16", "w-8", "w-12", "w-32", "w-16"];

export function SkeletonRows({
  columns,
  rows = 10,
}: {
  columns: number;
  rows?: number;
}) {
  return (
    <>
      {Array.from({ length: rows }).map((_, row) => (
        <tr key={row} className="border-b border-line-soft border-l-2 border-l-transparent">
          {Array.from({ length: columns }).map((__, column) => (
            <td key={column} className="px-3 py-1">
              <span
                className={cn(
                  "block h-3 animate-pulse bg-line",
                  WIDTHS[column % WIDTHS.length],
                  column === 3 || column === 6 ? "ml-auto" : "",
                )}
                style={{ animationDelay: `${row * 40}ms` }}
              />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}
