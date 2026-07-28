"use client";

import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, ScrollText, ShieldAlert } from "lucide-react";
import { useState } from "react";

import { EmptyState, ErrorState, PageHeader, TableSkeleton } from "@/components/common";
import { Badge, outcomeVariant } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ApiError, api } from "@/lib/api-client";
import { useAuth } from "@/lib/auth-provider";
import { Permission } from "@/lib/permissions";
import { absoluteTime, humanizeAction, relativeTime } from "@/lib/utils";

export default function AuditPage() {
  const { can } = useAuth();
  const [actionFilter, setActionFilter] = useState("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [expanded, setExpanded] = useState<string | null>(null);

  const events = useQuery({
    queryKey: ["audit", actionFilter, cursor ?? "first"],
    queryFn: () =>
      api.audit.list({
        limit: 50,
        ...(actionFilter ? { action: actionFilter } : {}),
        ...(cursor ? { cursor } : {}),
      }),
    enabled: can(Permission.AUDIT_READ),
  });

  const chain = useQuery({
    queryKey: ["audit", "verify"],
    queryFn: () => api.audit.verify(),
    enabled: can(Permission.AUDIT_READ),
  });

  if (!can(Permission.AUDIT_READ)) {
    return <ErrorState error={new ApiError(403, null, "Your role does not include audit:read.")} />;
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit log"
        description="Append-only and hash-chained. Reading it is itself recorded."
      />

      <Card>
        <CardContent className="flex flex-wrap items-center gap-4 p-5">
          {chain.isLoading ? (
            <p className="text-sm text-muted-foreground">Verifying the chain…</p>
          ) : chain.data?.intact ? (
            <>
              <span className="flex size-9 items-center justify-center rounded-full bg-status-online-surface text-status-online">
                <CheckCircle2 className="size-5" />
              </span>
              <div>
                <p className="text-sm font-medium">Chain intact</p>
                <p className="text-xs text-muted-foreground">
                  {chain.data.entries_checked.toLocaleString()} entries verified from genesis.
                  Each entry hashes its predecessor, so a removed or altered row breaks
                  every link after it.
                </p>
              </div>
            </>
          ) : (
            <>
              <span className="flex size-9 items-center justify-center rounded-full bg-severity-critical-surface text-severity-critical">
                <ShieldAlert className="size-5" />
              </span>
              <div>
                <p className="text-sm font-medium text-severity-critical">Chain broken</p>
                <p className="text-xs text-muted-foreground">
                  First break at sequence {chain.data?.first_broken_sequence ?? "unknown"} after{" "}
                  {chain.data?.entries_checked ?? 0} entries. Treat this as an integrity
                  incident.
                </p>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      <form
        className="flex max-w-md items-center gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          setCursor(undefined);
        }}
      >
        <Input
          value={actionFilter}
          onChange={(event) => {
            setActionFilter(event.target.value);
            setCursor(undefined);
          }}
          placeholder="Filter by action, e.g. security.token_reuse"
          aria-label="Filter by action"
          className="font-mono text-xs"
        />
      </form>

      <Card>
        <CardContent className="p-0">
          {events.isLoading ? (
            <TableSkeleton rows={8} columns={5} />
          ) : events.isError ? (
            <ErrorState error={events.error} onRetry={() => void events.refetch()} />
          ) : (events.data?.items.length ?? 0) === 0 ? (
            <EmptyState
              icon={<ScrollText className="size-5" />}
              title="No matching entries"
              description={actionFilter ? "Try clearing the action filter." : undefined}
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-16">Seq</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>Outcome</TableHead>
                  <TableHead>When</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.data?.items.map((event) => (
                  <>
                    <TableRow
                      key={event.id}
                      className="cursor-pointer"
                      onClick={() => setExpanded(expanded === event.id ? null : event.id)}
                    >
                      <TableCell className="font-mono text-2xs text-muted-foreground">
                        {event.sequence}
                      </TableCell>
                      <TableCell>
                        <span className="font-medium">{humanizeAction(event.action)}</span>
                        <p className="font-mono text-2xs text-muted-foreground">{event.action}</p>
                      </TableCell>
                      <TableCell>
                        <span className="text-sm">{event.actor_label || "system"}</span>
                        <p className="text-2xs text-muted-foreground">{event.actor_type}</p>
                      </TableCell>
                      <TableCell>
                        <Badge variant={outcomeVariant(event.outcome)}>{event.outcome}</Badge>
                      </TableCell>
                      <TableCell
                        className="whitespace-nowrap text-xs text-muted-foreground"
                        title={absoluteTime(event.occurred_at)}
                      >
                        {relativeTime(event.occurred_at)}
                      </TableCell>
                    </TableRow>
                    {expanded === event.id ? (
                      <TableRow key={`${event.id}-detail`} className="bg-muted/40 hover:bg-muted/40">
                        <TableCell colSpan={5}>
                          <dl className="grid gap-x-6 gap-y-2 text-xs sm:grid-cols-3">
                            <div>
                              <dt className="text-muted-foreground">Resource</dt>
                              <dd className="font-mono">
                                {event.resource_type || "—"}
                                {event.resource_id ? ` ${event.resource_id.slice(0, 8)}…` : ""}
                              </dd>
                            </div>
                            <div>
                              <dt className="text-muted-foreground">Source IP</dt>
                              <dd className="font-mono">{event.ip_address ?? "—"}</dd>
                            </div>
                            <div>
                              <dt className="text-muted-foreground">Request</dt>
                              <dd className="font-mono">{event.request_id || "—"}</dd>
                            </div>
                            <div className="sm:col-span-3">
                              <dt className="text-muted-foreground">Recorded at</dt>
                              <dd>{absoluteTime(event.occurred_at)}</dd>
                            </div>
                            {Object.keys(event.metadata).length > 0 ? (
                              <div className="sm:col-span-3">
                                <dt className="text-muted-foreground">Metadata</dt>
                                <dd>
                                  <pre className="mt-1 overflow-x-auto rounded-md border border-border bg-card p-3 font-mono text-2xs">
                                    {JSON.stringify(event.metadata, null, 2)}
                                  </pre>
                                </dd>
                              </div>
                            ) : null}
                          </dl>
                        </TableCell>
                      </TableRow>
                    ) : null}
                  </>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {events.data?.page.has_more || cursor ? (
        <div className="flex items-center justify-between">
          <Button variant="outline" size="sm" disabled={!cursor} onClick={() => setCursor(undefined)}>
            Newest
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={!events.data?.page.has_more}
            onClick={() => setCursor(events.data?.page.next_cursor ?? undefined)}
          >
            Older entries
          </Button>
        </div>
      ) : null}
    </div>
  );
}
