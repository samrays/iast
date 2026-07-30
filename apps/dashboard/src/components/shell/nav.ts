import {
  Activity,
  Boxes,
  KeyRound,
  LayoutDashboard,
  ScrollText,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Users,
  type LucideIcon,
} from "lucide-react";

import { Permission, type PermissionValue } from "@/lib/permissions";

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  /** Hidden when the principal holds none of these. Never the enforcement point. */
  requires?: PermissionValue[];
  description: string;
}

export interface NavSection {
  title: string;
  items: NavItem[];
}

export const NAV_SECTIONS: NavSection[] = [
  {
    title: "Monitor",
    items: [
      {
        href: "/",
        label: "Overview",
        icon: LayoutDashboard,
        description: "Portfolio posture and fleet health at a glance",
      },
      {
        href: "/findings",
        label: "Findings",
        icon: ShieldAlert,
        requires: [Permission.FINDING_READ],
        description: "Vulnerabilities observed in running applications",
      },
      {
        href: "/applications",
        label: "Applications",
        icon: Boxes,
        requires: [Permission.APP_READ],
        description: "Every service under test and its environments",
      },
      {
        href: "/agents",
        label: "Agent fleet",
        icon: Activity,
        requires: [Permission.AGENT_READ],
        description: "Runtime agents, overhead and coverage",
      },
    ],
  },
  {
    title: "Govern",
    items: [
      {
        href: "/rules",
        label: "Detection rules",
        icon: ShieldCheck,
        requires: [Permission.POLICY_READ],
        description:
          "What the agent looks for, and what this organization has switched off",
      },
      {
        href: "/members",
        label: "Members",
        icon: Users,
        requires: [Permission.ORG_READ],
        description: "People in this organization and their roles",
      },
      {
        href: "/roles",
        label: "Roles",
        icon: ShieldCheck,
        requires: [Permission.ORG_READ],
        description: "System and custom permission bundles",
      },
      {
        href: "/api-keys",
        label: "API keys",
        icon: KeyRound,
        requires: [Permission.SETTINGS_WRITE],
        description: "Credentials for CI and agent bootstrap",
      },
      {
        href: "/audit",
        label: "Audit log",
        icon: ScrollText,
        requires: [Permission.AUDIT_READ],
        description: "Tamper-evident record of every privileged action",
      },
    ],
  },
  {
    title: "Configure",
    items: [
      {
        href: "/settings",
        label: "Settings",
        icon: Settings,
        description: "Organization, security and appearance",
      },
    ],
  },
];

export function visibleSections(permissions: string[]): NavSection[] {
  return NAV_SECTIONS.map((section) => ({
    ...section,
    items: section.items.filter(
      (item) =>
        !item.requires ||
        item.requires.some((permission) => permissions.includes(permission)),
    ),
  })).filter((section) => section.items.length > 0);
}
