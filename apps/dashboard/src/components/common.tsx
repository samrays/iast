"use client";

import { AlertTriangle, Check, Copy, Inbox, ShieldAlert } from "lucide-react";
import { useCallback, useState, type ReactNode } from "react";

import { ApiError } from "@/lib/api-client";
import { cn } from "@/lib/utils";

import { Button } from "./ui/button";
import { Card, CardContent } from "./ui/card";
import { Skeleton } from "./ui/misc";
import { Table, TableBody, TableCell, TableRow } from "./ui/table";

// --- page furniture ----------------------------------------------------------------

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
      <div className="min-w-0">
        <h1 className="truncate text-2xl font-semibold tracking-tight">{title}</h1>
        {description ? (
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">{description}</p>
        ) : null}
      </div>
      {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
    </div>
  );
}

// --- states ------------------------------------------------------------------------

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-16 text-center">
      <div className="flex size-11 items-center justify-center rounded-full bg-muted text-muted-foreground">
        {icon ?? <Inbox className="size-5" />}
      </div>
      <div>
        <p className="font-medium">{title}</p>
        {description ? (
          <p className="mt-1 max-w-md text-sm text-muted-foreground">{description}</p>
        ) : null}
      </div>
      {action}
    </div>
  );
}

/**
 * Error presentation that distinguishes "you may not" from "something broke".
 *
 * A 403 rendered as a red crash banner teaches people the tool is unreliable; it is not,
 * they simply lack a permission and should be told so calmly.
 */
export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const apiError = error instanceof ApiError ? error : null;
  const isPermission = apiError?.status === 403;
  const isMissing = apiError?.status === 404;

  const title = isPermission
    ? "You do not have access to this"
    : isMissing
      ? "Not found"
      : "Something went wrong";

  const detail =
    apiError?.problem?.detail ??
    (error instanceof Error ? error.message : "An unexpected error occurred.");

  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-16 text-center">
      <div
        className={cn(
          "flex size-11 items-center justify-center rounded-full",
          isPermission
            ? "bg-severity-medium-surface text-severity-medium"
            : "bg-severity-critical-surface text-severity-critical",
        )}
      >
        {isPermission ? <ShieldAlert className="size-5" /> : <AlertTriangle className="size-5" />}
      </div>
      <div>
        <p className="font-medium">{title}</p>
        <p className="mt-1 max-w-md text-sm text-muted-foreground">{detail}</p>
        {apiError?.requestId ? (
          <p className="mt-2 font-mono text-2xs text-muted-foreground">
            request {apiError.requestId}
          </p>
        ) : null}
      </div>
      {onRetry && !isPermission ? (
        <Button variant="outline" size="sm" onClick={onRetry}>
          Try again
        </Button>
      ) : null}
    </div>
  );
}

export function TableSkeleton({ rows = 5, columns = 4 }: { rows?: number; columns?: number }) {
  return (
    <Table>
      <TableBody>
        {Array.from({ length: rows }).map((_, rowIndex) => (
          <TableRow key={rowIndex}>
            {Array.from({ length: columns }).map((__, columnIndex) => (
              <TableCell key={columnIndex}>
                <Skeleton className="h-4 w-full max-w-[12rem]" />
              </TableCell>
            ))}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

// --- stat tile ---------------------------------------------------------------------

export function StatTile({
  label,
  value,
  hint,
  tone = "default",
  icon,
}: {
  label: string;
  value: string | number;
  hint?: string;
  tone?: "default" | "critical" | "warning" | "positive";
  icon?: ReactNode;
}) {
  const toneClass = {
    default: "text-foreground",
    critical: "text-severity-critical",
    warning: "text-severity-medium",
    positive: "text-status-online",
  }[tone];

  return (
    <Card>
      <CardContent className="flex items-start justify-between gap-4 p-5">
        <div className="min-w-0">
          <p className="text-2xs font-semibold uppercase tracking-wide text-muted-foreground">
            {label}
          </p>
          {/* Tabular figures stop the number jittering as it updates. */}
          <p className={cn("mt-2 text-3xl font-semibold tabular-nums leading-none", toneClass)}>
            {value}
          </p>
          {hint ? <p className="mt-2 truncate text-xs text-muted-foreground">{hint}</p> : null}
        </div>
        {icon ? <div className="shrink-0 text-muted-foreground">{icon}</div> : null}
      </CardContent>
    </Card>
  );
}

// --- copy to clipboard --------------------------------------------------------------

export function CopyButton({
  value,
  label = "Copy",
  className,
}: {
  value: string;
  label?: string;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);

  const copy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      // Clipboard access can be denied; the value is on screen either way.
    }
  }, [value]);

  return (
    <Button variant="outline" size="sm" onClick={copy} className={className}>
      {copied ? <Check className="text-status-online" /> : <Copy />}
      {copied ? "Copied" : label}
    </Button>
  );
}

// --- key/value list -----------------------------------------------------------------

export function DetailList({ items }: { items: Array<{ label: string; value: ReactNode }> }) {
  return (
    <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
      {items.map((item) => (
        <div key={item.label} className="min-w-0">
          <dt className="text-2xs font-semibold uppercase tracking-wide text-muted-foreground">
            {item.label}
          </dt>
          <dd className="mt-1 break-words text-sm">{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}
