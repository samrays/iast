"use client";

import { useQuery } from "@tanstack/react-query";
import { Command } from "cmdk";
import { useRouter } from "next/navigation";
import { useTheme } from "next-themes";
import { Boxes, LogOut, Moon, Search, Sun } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { api } from "@/lib/api-client";
import { useAuth } from "@/lib/auth-provider";
import { Permission } from "@/lib/permissions";
import { cn } from "@/lib/utils";

import { visibleSections } from "./nav";

/**
 * Global search and command palette (⌘K / Ctrl-K).
 *
 * Search is server-side against the applications endpoint rather than a client-side filter
 * over a fetched page: the portfolio is larger than one page, and filtering only what
 * happens to be loaded is the kind of half-truth that makes people distrust a search box.
 */
export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const router = useRouter();
  const { permissions, logout, can } = useAuth();
  const { setTheme, resolvedTheme } = useTheme();

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "k" && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        setOpen((value) => !value);
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  const trimmed = query.trim();
  const { data: applications } = useQuery({
    queryKey: ["command-search", trimmed],
    queryFn: () => api.applications.list({ q: trimmed, limit: 6 }),
    enabled: open && trimmed.length >= 2 && can(Permission.APP_READ),
    staleTime: 10_000,
  });

  const navItems = useMemo(
    () => visibleSections(permissions).flatMap((section) => section.items),
    [permissions],
  );

  const go = (href: string) => {
    setOpen(false);
    setQuery("");
    router.push(href);
  };

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className={cn(
          "flex h-9 w-full max-w-xs items-center gap-2 rounded-md border border-input bg-card px-3 text-sm text-muted-foreground",
          "transition-colors hover:bg-accent/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        )}
      >
        <Search className="size-4 shrink-0" aria-hidden />
        <span className="truncate">Search…</span>
        <kbd className="ml-auto hidden shrink-0 rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-2xs sm:inline">
          ⌘K
        </kbd>
      </button>

      <Command.Dialog
        open={open}
        onOpenChange={setOpen}
        label="Global command palette"
        shouldFilter={false}
        className="fixed left-1/2 top-[15%] z-50 w-[min(36rem,calc(100vw-2rem))] -translate-x-1/2 overflow-hidden rounded-lg border border-border bg-popover shadow-2xl"
      >
        <div className="flex items-center gap-2 border-b border-border px-4">
          <Search className="size-4 shrink-0 text-muted-foreground" aria-hidden />
          <Command.Input
            value={query}
            onValueChange={setQuery}
            placeholder="Search applications, or jump to a page…"
            className="h-12 w-full bg-transparent text-sm outline-none placeholder:text-muted-foreground"
          />
        </div>

        <Command.List className="max-h-80 overflow-y-auto p-2">
          <Command.Empty className="px-3 py-8 text-center text-sm text-muted-foreground">
            {trimmed.length >= 2 ? "No matches." : "Type at least two characters to search."}
          </Command.Empty>

          {applications && applications.items.length > 0 ? (
            <Command.Group
              heading="Applications"
              className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-2xs [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wide [&_[cmdk-group-heading]]:text-muted-foreground"
            >
              {applications.items.map((application) => (
                <Command.Item
                  key={application.id}
                  value={application.id}
                  onSelect={() => go(`/applications/${application.id}`)}
                  className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm data-[selected=true]:bg-accent data-[selected=true]:text-accent-foreground"
                >
                  <Boxes className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                  <span className="truncate">{application.name}</span>
                  <span className="ml-auto shrink-0 font-mono text-2xs text-muted-foreground">
                    {application.language}
                  </span>
                </Command.Item>
              ))}
            </Command.Group>
          ) : null}

          <Command.Group
            heading="Go to"
            className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-2xs [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wide [&_[cmdk-group-heading]]:text-muted-foreground"
          >
            {navItems
              .filter(
                (item) =>
                  trimmed.length === 0 ||
                  item.label.toLowerCase().includes(trimmed.toLowerCase()),
              )
              .map((item) => (
                <Command.Item
                  key={item.href}
                  value={item.href}
                  onSelect={() => go(item.href)}
                  className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm data-[selected=true]:bg-accent data-[selected=true]:text-accent-foreground"
                >
                  <item.icon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                  <span className="truncate">{item.label}</span>
                  <span className="ml-auto hidden truncate text-2xs text-muted-foreground sm:block">
                    {item.description}
                  </span>
                </Command.Item>
              ))}
          </Command.Group>

          <Command.Group
            heading="Actions"
            className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-2xs [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wide [&_[cmdk-group-heading]]:text-muted-foreground"
          >
            <Command.Item
              value="toggle-theme"
              onSelect={() => {
                setTheme(resolvedTheme === "dark" ? "light" : "dark");
                setOpen(false);
              }}
              className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm data-[selected=true]:bg-accent data-[selected=true]:text-accent-foreground"
            >
              {resolvedTheme === "dark" ? (
                <Sun className="size-4 text-muted-foreground" aria-hidden />
              ) : (
                <Moon className="size-4 text-muted-foreground" aria-hidden />
              )}
              Switch to {resolvedTheme === "dark" ? "light" : "dark"} theme
            </Command.Item>
            <Command.Item
              value="sign-out"
              onSelect={() => {
                setOpen(false);
                void logout();
              }}
              className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm text-destructive data-[selected=true]:bg-destructive/10"
            >
              <LogOut className="size-4" aria-hidden />
              Sign out
            </Command.Item>
          </Command.Group>
        </Command.List>
      </Command.Dialog>
    </>
  );
}
