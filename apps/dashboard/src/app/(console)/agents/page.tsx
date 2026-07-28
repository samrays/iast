"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, Power, PowerOff } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { EmptyState, ErrorState, PageHeader, StatTile, TableSkeleton } from "@/components/common";
import { Badge, agentStatusVariant } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/misc";
import { ApiError, api } from "@/lib/api-client";
import { useAuth } from "@/lib/auth-provider";
import { Permission } from "@/lib/permissions";
import { AGENT_STATUSES } from "@/lib/types";
import { cn, relativeTime } from "@/lib/utils";

/** The overhead budget the agent's own resource governor enforces (docs/05 §6). */
const OVERHEAD_BUDGET_PCT = 5;

export default function AgentsPage() {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const [statusFilter, setStatusFilter] = useState<string>("ALL");

  const agents = useQuery({
    queryKey: ["agents", statusFilter],
    queryFn: () =>
      api.agents.list({ limit: 100, ...(statusFilter === "ALL" ? {} : { status: statusFilter }) }),
    enabled: can(Permission.AGENT_READ),
    refetchInterval: 20_000,
  });

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.agents.update(id, { enabled }),
    onSuccess: (agent) => {
      toast.success(
        agent.status === "DISABLED"
          ? `${agent.hostname} disabled — its credential stops working immediately.`
          : `${agent.hostname} re-enabled.`,
      );
      void queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
    onError: (error) =>
      toast.error(error instanceof ApiError ? error.message : "Could not update the agent."),
  });

  if (!can(Permission.AGENT_READ)) {
    return <ErrorState error={new ApiError(403, null, "Your role does not include agent:read.")} />;
  }

  const items = agents.data?.items ?? [];
  const online = items.filter((agent) => agent.status === "ONLINE").length;
  const degraded = items.filter((agent) => agent.status === "DEGRADED").length;
  const offline = items.filter((agent) => agent.status === "OFFLINE").length;
  const dropped = items.reduce((total, agent) => total + agent.events_dropped, 0);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Agent fleet"
        description="Runtime agents live inside your applications. Their health is the coverage story."
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile label="Online" value={online} tone="positive" hint="Reporting normally" />
        <StatTile
          label="Degraded"
          value={degraded}
          tone={degraded > 0 ? "warning" : "default"}
          hint={`Over the ${OVERHEAD_BUDGET_PCT}% budget or with hooks disabled`}
        />
        <StatTile
          label="Offline"
          value={offline}
          tone={offline > 0 ? "critical" : "default"}
          hint="No heartbeat for 90 seconds"
        />
        <StatTile
          label="Events dropped"
          value={dropped}
          tone={dropped > 0 ? "warning" : "default"}
          hint="Shed by the agent's bounded buffer"
        />
      </div>

      <div className="flex items-center gap-2">
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-48" aria-label="Filter by status">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="ALL">All statuses</SelectItem>
            {AGENT_STATUSES.map((status) => (
              <SelectItem key={status} value={status}>
                {status}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <p className="text-xs text-muted-foreground">Refreshes every 20 seconds.</p>
      </div>

      <Card>
        <CardContent className="p-0">
          {agents.isLoading ? (
            <TableSkeleton rows={6} columns={6} />
          ) : agents.isError ? (
            <ErrorState error={agents.error} onRetry={() => void agents.refetch()} />
          ) : items.length === 0 ? (
            <EmptyState
              icon={<Activity className="size-5" />}
              title={statusFilter === "ALL" ? "No agents registered" : `No ${statusFilter} agents`}
              description={
                statusFilter === "ALL"
                  ? "Issue an API key with agent:write, then start an agent pointing at this control plane."
                  : "Try a different status filter."
              }
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Host</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Runtime</TableHead>
                  <TableHead>CPU overhead</TableHead>
                  <TableHead>Events</TableHead>
                  <TableHead>Last seen</TableHead>
                  {can(Permission.AGENT_WRITE) ? <TableHead /> : null}
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((agent) => {
                  const overBudget =
                    agent.cpu_overhead_pct !== null && agent.cpu_overhead_pct > OVERHEAD_BUDGET_PCT;
                  return (
                    <TableRow key={agent.id}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          {agent.status === "ONLINE" ? (
                            <span className="relative flex size-2 shrink-0 text-status-online">
                              <span className="size-2 rounded-full bg-current" />
                            </span>
                          ) : null}
                          <span className="font-medium">{agent.hostname}</span>
                        </div>
                        <p className="font-mono text-2xs text-muted-foreground">
                          {agent.fingerprint.slice(0, 20)}…
                        </p>
                      </TableCell>
                      <TableCell>
                        <Badge variant={agentStatusVariant(agent.status)}>{agent.status}</Badge>
                        {agent.pinned_version ? (
                          <Badge variant="outline" className="ml-1">
                            pinned
                          </Badge>
                        ) : null}
                      </TableCell>
                      <TableCell>
                        <span className="font-mono text-xs">{agent.language}</span>
                        <p className="text-2xs text-muted-foreground">
                          agent {agent.agent_version}
                          {agent.runtime_version ? ` · ${agent.runtime_version}` : ""}
                        </p>
                      </TableCell>
                      <TableCell>
                        {agent.cpu_overhead_pct === null ? (
                          <span className="text-xs text-muted-foreground">—</span>
                        ) : (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span
                                className={cn(
                                  "tabular-nums text-sm",
                                  overBudget && "font-semibold text-severity-high",
                                )}
                              >
                                {agent.cpu_overhead_pct}%
                              </span>
                            </TooltipTrigger>
                            <TooltipContent>
                              Budget is {OVERHEAD_BUDGET_PCT}%. Above it the agent degrades
                              itself rather than slow your application.
                            </TooltipContent>
                          </Tooltip>
                        )}
                      </TableCell>
                      <TableCell className="tabular-nums text-xs">
                        {agent.events_sent.toLocaleString()} sent
                        {agent.events_dropped > 0 ? (
                          <span className="block text-severity-medium">
                            {agent.events_dropped.toLocaleString()} dropped
                          </span>
                        ) : null}
                      </TableCell>
                      <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                        {relativeTime(agent.last_seen_at)}
                      </TableCell>
                      {can(Permission.AGENT_WRITE) ? (
                        <TableCell className="text-right">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() =>
                              toggle.mutate({
                                id: agent.id,
                                enabled: agent.status === "DISABLED",
                              })
                            }
                          >
                            {agent.status === "DISABLED" ? <Power /> : <PowerOff />}
                            {agent.status === "DISABLED" ? "Enable" : "Disable"}
                          </Button>
                        </TableCell>
                      ) : null}
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
