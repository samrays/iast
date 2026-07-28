"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldHalf } from "lucide-react";

import { useAuth } from "@/lib/auth-provider";
import { cn } from "@/lib/utils";

import { visibleSections } from "./nav";

export function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname();
  const { permissions, principal } = useAuth();
  const sections = visibleSections(permissions);

  return (
    <nav aria-label="Primary" className="flex h-full flex-col gap-6 overflow-y-auto p-4">
      <Link
        href="/"
        onClick={onNavigate}
        className="flex items-center gap-2.5 rounded-md px-2 py-1.5 transition-colors hover:bg-accent/60"
      >
        <span className="flex size-8 items-center justify-center rounded-md bg-primary text-primary-foreground">
          <ShieldHalf className="size-4.5" />
        </span>
        <span className="min-w-0">
          <span className="block truncate text-sm font-semibold leading-tight">Aegis IAST</span>
          <span className="block truncate text-2xs text-muted-foreground">
            {principal?.organization.name ?? " "}
          </span>
        </span>
      </Link>

      <div className="flex flex-1 flex-col gap-6">
        {sections.map((section) => (
          <div key={section.title}>
            <p className="px-2 pb-2 text-2xs font-semibold uppercase tracking-wide text-muted-foreground">
              {section.title}
            </p>
            <ul className="flex flex-col gap-0.5">
              {section.items.map((item) => {
                // Exact match for the root so every route does not light up "Overview".
                const active =
                  item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      onClick={onNavigate}
                      aria-current={active ? "page" : undefined}
                      className={cn(
                        "flex items-center gap-2.5 rounded-md px-2 py-2 text-sm transition-colors",
                        active
                          ? "bg-accent font-medium text-accent-foreground"
                          : "text-muted-foreground hover:bg-accent/50 hover:text-foreground",
                      )}
                    >
                      <item.icon className="size-4 shrink-0" aria-hidden />
                      <span className="truncate">{item.label}</span>
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </div>

      <p className="px-2 text-2xs text-muted-foreground">
        Phase 3 console · findings and attack response arrive in Phase 5.
      </p>
    </nav>
  );
}
