import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** Compose class names, letting later Tailwind utilities win over earlier ones. */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

/**
 * Relative time, in the terse form an operator scanning a table wants.
 *
 * "3m ago" beats "3 minutes ago" when the column is 90px wide and there are forty rows.
 */
export function relativeTime(value: string | null | undefined): string {
  if (!value) return "never";
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return "unknown";

  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 0) return "just now";
  if (seconds < 45) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days}d ago`;
  const months = Math.round(days / 30);
  if (months < 12) return `${months}mo ago`;
  return `${Math.round(months / 12)}y ago`;
}

/** Absolute timestamp for tooltips and detail panes, where precision matters. */
export function absoluteTime(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "short",
  });
}

/** Compact counts for stat tiles: 1_284 → "1.3k". */
export function compactNumber(value: number): string {
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(
    value,
  );
}

/** Title-case an API enum for display: `PENDING_DELETION` → `Pending deletion`. */
export function humanizeEnum(value: string): string {
  const lower = value.toLowerCase().replace(/_/g, " ");
  return lower.charAt(0).toUpperCase() + lower.slice(1);
}

/** Turn `application.created` into `Application created`. */
export function humanizeAction(action: string): string {
  const [, tail] = action.includes(".") ? action.split(".") : ["", action];
  return humanizeEnum(tail ?? action);
}

/** Two-letter monogram for an avatar, from a name or an email address. */
export function initials(name: string, fallback = ""): string {
  const source = name.trim() || fallback.trim();
  if (!source) return "?";
  const parts = source.replace(/@.*/, "").split(/[\s._-]+/).filter(Boolean);
  if (parts.length === 0) return "?";
  if (parts.length === 1) return (parts[0] ?? "").slice(0, 2).toUpperCase();
  return `${(parts[0] ?? "").charAt(0)}${(parts[1] ?? "").charAt(0)}`.toUpperCase();
}

/** Sentence-case a permission for display: `finding:triage` → `Triage findings`. */
export function describePermission(permission: string): string {
  const [resource = "", action = ""] = permission.split(":");
  return `${humanizeEnum(action)} ${resource.replace(/_/g, " ")}`;
}
