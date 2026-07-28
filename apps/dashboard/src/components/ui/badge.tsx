import { cva, type VariantProps } from "class-variance-authority";
import type { HTMLAttributes } from "react";

import { cn } from "@/lib/utils";

/**
 * Status and severity badges.
 *
 * Severity and fleet status get their own variants rather than being expressed with
 * arbitrary colour classes at each call site — that is how a "critical" ends up amber on
 * one screen and red on another.
 */
const badgeVariants = cva(
  "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-2xs font-semibold uppercase tracking-wide transition-colors",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary/10 text-primary",
        secondary: "border-transparent bg-secondary text-secondary-foreground",
        outline: "border-border text-muted-foreground",
        critical: "border-transparent bg-severity-critical-surface text-severity-critical",
        high: "border-transparent bg-severity-high-surface text-severity-high",
        medium: "border-transparent bg-severity-medium-surface text-severity-medium",
        low: "border-transparent bg-severity-low-surface text-severity-low",
        info: "border-transparent bg-severity-info-surface text-severity-info",
        online: "border-transparent bg-status-online-surface text-status-online",
        degraded: "border-transparent bg-status-degraded-surface text-status-degraded",
        offline: "border-transparent bg-status-offline-surface text-status-offline",
        disabled: "border-transparent bg-status-disabled-surface text-status-disabled",
        success: "border-transparent bg-status-online-surface text-status-online",
        danger: "border-transparent bg-severity-critical-surface text-severity-critical",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

export interface BadgeProps
  extends HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}

/** Map an agent status onto its badge variant, in one place. */
export function agentStatusVariant(status: string): BadgeProps["variant"] {
  switch (status) {
    case "ONLINE":
      return "online";
    case "DEGRADED":
      return "degraded";
    case "OFFLINE":
      return "offline";
    case "DISABLED":
      return "disabled";
    default:
      return "outline";
  }
}

/** Map an application criticality onto its severity variant. */
export function criticalityVariant(criticality: string): BadgeProps["variant"] {
  switch (criticality) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      return "info";
  }
}

/** Protection mode: blocking is the loud one, because it can break a request. */
export function protectionVariant(mode: string): BadgeProps["variant"] {
  switch (mode) {
    case "BLOCK":
      return "critical";
    case "MONITOR":
      return "low";
    default:
      return "outline";
  }
}

export function outcomeVariant(outcome: string): BadgeProps["variant"] {
  switch (outcome) {
    case "SUCCESS":
      return "success";
    case "DENIED":
      return "danger";
    case "FAILURE":
      return "medium";
    default:
      return "outline";
  }
}

export { badgeVariants };
