"use client";

import { useQuery } from "@tanstack/react-query";
import { useTheme } from "next-themes";
import Link from "next/link";
import { Bell, LogOut, Menu, Moon, Settings, Sun, UserRound } from "lucide-react";
import { useEffect, useState } from "react";

import { api } from "@/lib/api-client";
import { useAuth } from "@/lib/auth-provider";
import { Permission } from "@/lib/permissions";
import { initials, relativeTime } from "@/lib/utils";

import { Badge, agentStatusVariant } from "../ui/badge";
import { Button } from "../ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "../ui/dropdown-menu";
import { Separator, Tooltip, TooltipContent, TooltipTrigger } from "../ui/misc";
import { CommandPalette } from "./command-palette";
import { Sidebar } from "./sidebar";

/**
 * Notifications are derived from fleet state rather than a dedicated feed: Phase 2 has no
 * notification endpoint, and inventing one client-side that only *looks* live would be
 * worse than showing the real signal the console already has.
 */
function useFleetAlerts(enabled: boolean) {
  return useQuery({
    queryKey: ["fleet-alerts"],
    queryFn: () => api.agents.list({ limit: 100 }),
    enabled,
    refetchInterval: 30_000,
    select: (page) => page.items.filter((agent) => agent.status === "DEGRADED" || agent.status === "OFFLINE"),
  });
}

export function Topbar() {
  const { principal, logout, can } = useAuth();
  const { setTheme, resolvedTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const { data: alerts } = useFleetAlerts(can(Permission.AGENT_READ));

  // The resolved theme is unknown until the client mounts; rendering an icon before that
  // guarantees a hydration mismatch.
  useEffect(() => setMounted(true), []);

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border bg-background/85 px-4 backdrop-blur">
      <Button
        variant="ghost"
        size="icon-sm"
        className="lg:hidden"
        aria-label="Open navigation"
        onClick={() => setMobileNavOpen((value) => !value)}
      >
        <Menu />
      </Button>

      <CommandPalette />

      <div className="ml-auto flex items-center gap-1">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon-sm" aria-label="Fleet alerts" className="relative">
              <Bell />
              {alerts && alerts.length > 0 ? (
                <span className="absolute right-1 top-1 flex size-2">
                  <span className="relative inline-flex size-2 rounded-full bg-severity-high" />
                </span>
              ) : null}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-80">
            <DropdownMenuLabel>Fleet alerts</DropdownMenuLabel>
            <DropdownMenuSeparator />
            {!alerts || alerts.length === 0 ? (
              <p className="px-2 py-6 text-center text-sm text-muted-foreground">
                Every agent is reporting normally.
              </p>
            ) : (
              alerts.slice(0, 6).map((agent) => (
                <DropdownMenuItem key={agent.id} asChild>
                  <Link href="/agents" className="flex items-start gap-2">
                    <Badge variant={agentStatusVariant(agent.status)}>{agent.status}</Badge>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm">{agent.hostname}</span>
                      <span className="block text-2xs text-muted-foreground">
                        last seen {relativeTime(agent.last_seen_at)}
                      </span>
                    </span>
                  </Link>
                </DropdownMenuItem>
              ))
            )}
          </DropdownMenuContent>
        </DropdownMenu>

        {mounted ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="icon-sm"
                aria-label={`Switch to ${resolvedTheme === "dark" ? "light" : "dark"} theme`}
                onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
              >
                {resolvedTheme === "dark" ? <Sun /> : <Moon />}
              </Button>
            </TooltipTrigger>
            <TooltipContent>
              {resolvedTheme === "dark" ? "Light theme" : "Dark theme"}
            </TooltipContent>
          </Tooltip>
        ) : (
          <span className="size-8" aria-hidden />
        )}

        <Separator orientation="vertical" className="mx-1 h-6" />

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" className="h-9 gap-2 px-2">
              <span className="flex size-6 items-center justify-center rounded-full bg-primary/10 text-2xs font-semibold text-primary">
                {initials(principal?.full_name ?? "", principal?.email ?? "")}
              </span>
              <span className="hidden max-w-[10rem] truncate text-sm sm:block">
                {principal?.full_name || principal?.email}
              </span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-64">
            <DropdownMenuLabel>Signed in</DropdownMenuLabel>
            <div className="px-2 pb-2">
              <p className="truncate text-sm font-medium">{principal?.full_name}</p>
              <p className="truncate text-xs text-muted-foreground">{principal?.email}</p>
              <div className="mt-2 flex flex-wrap gap-1">
                {principal?.roles.map((role) => (
                  <Badge key={role.id} variant="outline">
                    {role.name}
                  </Badge>
                ))}
              </div>
            </div>
            <DropdownMenuSeparator />
            <DropdownMenuItem asChild>
              <Link href="/settings">
                <UserRound />
                Account and security
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <Link href="/settings">
                <Settings />
                Organization settings
              </Link>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem destructive onSelect={() => void logout()}>
              <LogOut />
              Sign out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      {mobileNavOpen ? (
        <div className="fixed inset-0 top-14 z-40 lg:hidden">
          <button
            type="button"
            aria-label="Close navigation"
            className="absolute inset-0 bg-foreground/30 backdrop-blur-sm"
            onClick={() => setMobileNavOpen(false)}
          />
          <div className="absolute left-0 top-0 h-full w-64 border-r border-border bg-card">
            <Sidebar onNavigate={() => setMobileNavOpen(false)} />
          </div>
        </div>
      ) : null}
    </header>
  );
}
