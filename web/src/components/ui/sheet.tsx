/** A right-hand drawer. Radix Dialog underneath; no animation library. */
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import * as React from "react";

import { cn } from "@/lib/format";

export const Sheet = DialogPrimitive.Root;

export const SheetContent = React.forwardRef<
  React.ElementRef<typeof DialogPrimitive.Content>,
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Content> & {
    title: React.ReactNode;
    description?: React.ReactNode;
  }
>(({ className, children, title, description, ...props }, ref) => (
  <DialogPrimitive.Portal>
    <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-black/60" />
    <DialogPrimitive.Content
      ref={ref}
      className={cn(
        "fixed inset-y-0 right-0 z-50 flex w-full max-w-[42rem] flex-col",
        "border-l border-line bg-panel shadow-2xl outline-none",
        className,
      )}
      {...props}
    >
      <div className="flex items-start justify-between gap-4 border-b border-line px-5 py-3.5">
        <div className="min-w-0">
          <DialogPrimitive.Title asChild>
            <div className="truncate text-sm font-semibold text-ink">{title}</div>
          </DialogPrimitive.Title>
          <DialogPrimitive.Description asChild>
            <div className="mt-0.5 truncate font-mono text-2xs text-ink-faint">
              {description}
            </div>
          </DialogPrimitive.Description>
        </div>
        <DialogPrimitive.Close
          aria-label="Close"
          className="shrink-0 p-1 text-ink-faint transition-colors hover:text-ink"
        >
          <X className="h-4 w-4" />
        </DialogPrimitive.Close>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>
    </DialogPrimitive.Content>
  </DialogPrimitive.Portal>
));
SheetContent.displayName = "SheetContent";
