"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { Activity, Boxes, Radar, ShieldAlert, TriangleAlert } from "lucide-react";
import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
  XAxis,
  YAxis,
} from "recharts";

import { DetailList, EmptyState, ErrorState, PageHeader, StatTile } from "@/components/common";
import { Badge, criticalityVariant, outcomeVariant } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/misc";
import { api } from "@/lib/api-client";
import { useAuth } from "@/lib/auth-provider";
import { Permission } from "@/lib/permissions";
import { humanizeAction, relativeTime } from "@/lib/utils";

const STATUS_ORDER = ["ONLINE", "DEGRADED", "OFFLINE", "REGISTERED", "DISABLED"] as const;
const STATUS_FILL: Record<string, string> = {
  ONLINE: "hsl(var(--status-online))",
  DEGRADED: "hsl(var(--status-degraded))",
  OFFLINE: "hsl(var(--status-offline))",
  REGISTERED: "hsl(var(--chart-1))",
  DISABLED: "hsl(var(--status-disabled))",
};

const CRITICALITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
const CRITICALITY_FILL: Record<string, string> = {
  CRITICAL: "hsl(var(--severity-critical))",
  HIGH: "hsl(var(--severity-high))",
  MEDIUM: "hsl(var(--severity-medium))",
  LOW: "hsl(var(--severity-low))",
};

export default function OverviewPage() {
  const { principal, can } = useAuth();

  const applications = useQuery({
    queryKey: ["applications", "overview"],
    queryFn: () => api.applications.list({ limit: 200 }),
    enabled: can(Permission.APP_READ),
  });

  const agents = useQuery({
    queryKey: ["agents", "overview"],
    queryFn: () => api.agents.list({ limit: 200 }),
    enabled: can(Permission.AGENT_READ),
    refetchInterval: 30_000,
  });

  const audit = useQuery({
    queryKey: ["audit", "overview"],
    queryFn: () => api.audit.list({ limit: 8 }),
    enabled: can(Permission.AUDIT_READ),
  });

  const applicationItems = applications.data?.items ?? [];
  const agentItems = agents.data?.items ?? [];

  const online = agentItems.filter((agent) => agent.status === "ONLINE").length;
  const unhealthy = agentItems.filter(
    (agent) => agent.status === "DEGRADED" || agent.status === "OFFLINE",
  ).length;
  const productionEnvironments = applicationItems.flatMap((application) =>
    application.environments.filter((environment) => environment.kind === "PRODUCTION"),
  );
  // An application with no agent is not "clean" — it is unobserved. That distinction is
  // the whole point of an IAST console and it belongs on the first screen.
  const environmentIdsWithAgents = new Set(agentItems.map((agent) => agent.application_environment_id));
  const unobserved = applicationItems.filter(
    (application) =>
      application.environments.length === 0 ||
      !application.environments.some((environment) => environmentIdsWithAgents.has(environment.id)),
  );

  const statusData = STATUS_ORDER.map((status) => ({
    status,
    count: agentItems.filter((agent) => agent.status === status).length,
  })).filter((entry) => entry.count > 0);

  const criticalityData = CRITICALITY_ORDER.map((criticality) => ({
    criticality,
    count: applicationItems.filter((application) => application.criticality === criticality).length,
  })).filter((entry) => entry.count > 0);

  const loading = applications.isLoading || agents.isLoading;

  return (
    <div className="space-y-6">
      <PageHeader
        title={`Good to see you, ${principal?.full_name?.split(" ")[0] ?? "there"}`}
        description={`Posture across ${principal?.organization.name ?? "your organization"}.`}
        actions={
          can(Permission.APP_WRITE) ? (
            <Button asChild>
              <Link href="/applications">
                <Boxes />
                Manage applications
              </Link>
            </Button>
          ) : null
        }
      />

      {loading ? (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, index) => (
            <Skeleton key={index} className="h-[7.5rem] w-full" />
          ))}
        </div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <StatTile
            label="Applications"
            value={applicationItems.length}
            hint={`${productionEnvironments.length} production environments`}
            icon={<Boxes className="size-5" />}
          />
          <StatTile
            label="Agents reporting"
            value={`${online}/${agentItems.length}`}
            hint={agentItems.length === 0 ? "No agents registered yet" : "Live in the last 90 seconds"}
            tone={agentItems.length > 0 && online === 0 ? "critical" : "positive"}
            icon={<Activity className="size-5" />}
          />
          <StatTile
            label="Needs attention"
            value={unhealthy}
            hint="Degraded or offline agents"
            tone={unhealthy > 0 ? "warning" : "default"}
            icon={<TriangleAlert className="size-5" />}
          />
          <StatTile
            label="Unobserved apps"
            value={unobserved.length}
            hint="No agent has ever reported"
            tone={unobserved.length > 0 ? "critical" : "positive"}
            icon={<Radar className="size-5" />}
          />
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Agent fleet by status</CardTitle>
            <CardDescription>
              Coverage is the leading indicator. Zero findings on an unobserved application
              means nothing.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {agents.isError ? (
              <ErrorState error={agents.error} onRetry={() => void agents.refetch()} />
            ) : statusData.length === 0 ? (
              <EmptyState
                icon={<Activity className="size-5" />}
                title="No agents have registered"
                description="Install an agent with an API key that holds agent:write. It will appear here within a heartbeat."
              />
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={statusData} margin={{ top: 8, right: 8, bottom: 0, left: -20 }}>
                  <XAxis
                    dataKey="status"
                    tickLine={false}
                    axisLine={false}
                    fontSize={11}
                    stroke="hsl(var(--muted-foreground))"
                  />
                  <YAxis
                    allowDecimals={false}
                    tickLine={false}
                    axisLine={false}
                    fontSize={11}
                    stroke="hsl(var(--muted-foreground))"
                  />
                  <RechartsTooltip
                    cursor={{ fill: "hsl(var(--muted) / 0.5)" }}
                    contentStyle={{
                      background: "hsl(var(--popover))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: "0.5rem",
                      fontSize: "0.8125rem",
                      color: "hsl(var(--popover-foreground))",
                    }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={64}>
                    {statusData.map((entry) => (
                      <Cell key={entry.status} fill={STATUS_FILL[entry.status]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Portfolio by criticality</CardTitle>
            <CardDescription>Drives risk weighting from Phase 5 onward.</CardDescription>
          </CardHeader>
          <CardContent>
            {criticalityData.length === 0 ? (
              <EmptyState title="No applications yet" description="Register one to get started." />
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <BarChart
                  data={criticalityData}
                  layout="vertical"
                  margin={{ top: 4, right: 12, bottom: 4, left: 8 }}
                >
                  <XAxis type="number" hide allowDecimals={false} />
                  <YAxis
                    type="category"
                    dataKey="criticality"
                    tickLine={false}
                    axisLine={false}
                    width={72}
                    fontSize={11}
                    stroke="hsl(var(--muted-foreground))"
                  />
                  <RechartsTooltip
                    cursor={{ fill: "hsl(var(--muted) / 0.5)" }}
                    contentStyle={{
                      background: "hsl(var(--popover))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: "0.5rem",
                      fontSize: "0.8125rem",
                      color: "hsl(var(--popover-foreground))",
                    }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={22}>
                    {criticalityData.map((entry) => (
                      <Cell key={entry.criticality} fill={CRITICALITY_FILL[entry.criticality]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Applications without coverage</CardTitle>
            <CardDescription>
              These report no runtime evidence at all. Treat them as unknown, not safe.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {unobserved.length === 0 ? (
              <EmptyState
                icon={<ShieldAlert className="size-5" />}
                title="Every application is observed"
                description="At least one agent is reporting for each registered environment."
              />
            ) : (
              <ul className="divide-y divide-border">
                {unobserved.slice(0, 6).map((application) => (
                  <li key={application.id}>
                    <Link
                      href={`/applications/${application.id}`}
                      className="flex items-center justify-between gap-3 py-2.5 transition-colors hover:text-primary"
                    >
                      <span className="min-w-0 truncate text-sm">{application.name}</span>
                      <Badge variant={criticalityVariant(application.criticality)}>
                        {application.criticality}
                      </Badge>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Recent activity</CardTitle>
            <CardDescription>From the tamper-evident audit chain.</CardDescription>
          </CardHeader>
          <CardContent>
            {!can(Permission.AUDIT_READ) ? (
              <EmptyState
                title="Audit access required"
                description="Your role does not include audit:read."
              />
            ) : audit.isLoading ? (
              <div className="space-y-2">
                {Array.from({ length: 5 }).map((_, index) => (
                  <Skeleton key={index} className="h-9 w-full" />
                ))}
              </div>
            ) : (audit.data?.items.length ?? 0) === 0 ? (
              <EmptyState title="Nothing recorded yet" />
            ) : (
              <ul className="divide-y divide-border">
                {audit.data?.items.map((event) => (
                  <li key={event.id} className="flex items-center gap-3 py-2.5">
                    <Badge variant={outcomeVariant(event.outcome)}>{event.outcome}</Badge>
                    <span className="min-w-0 flex-1 truncate text-sm">
                      {humanizeAction(event.action)}
                      <span className="text-muted-foreground"> · {event.actor_label || "system"}</span>
                    </span>
                    <span className="shrink-0 text-2xs text-muted-foreground">
                      {relativeTime(event.occurred_at)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">What lands next</CardTitle>
          <CardDescription>
            This console shows everything the Phase 2 control plane knows. It shows nothing
            it does not — no placeholder findings, no invented metrics.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <DetailList
            items={[
              {
                label: "Phase 4",
                value: "Java agent and ingest gateway — first real runtime evidence",
              },
              {
                label: "Phase 5",
                value: "Findings, risk scoring, attack timeline and protection policy",
              },
              { label: "Phase 6", value: "AI root cause and remediation, with approval gates" },
              { label: "Phase 7", value: "Reporting, compliance posture and executive rollups" },
            ]}
          />
        </CardContent>
      </Card>
    </div>
  );
}
