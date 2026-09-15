"use client";

import { useQuery } from "@tanstack/react-query";
import { ShieldAlert } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";

import { EmptyState, ErrorState, PageHeader, TableSkeleton } from "@/components/common";
import { Badge, findingStatusVariant, severityVariant } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
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
import { ApiError, api } from "@/lib/api-client";
import { useAuth } from "@/lib/auth-provider";
import { Permission } from "@/lib/permissions";
import { relativeTime } from "@/lib/utils";

const STATUS_FILTERS = ["OPEN", "CONFIRMED", "REMEDIATED", "FALSE_POSITIVE", "ACCEPTED_RISK"];

export default function FindingsPage() {
  const { can } = useAuth();
  // Open work first. Someone arriving at this screen wants the queue, not the archive.
  const [statuses, setStatuses] = useState<string[]>(["OPEN", "CONFIRMED"]);
  const [search, setSearch] = useState("");
  const [applicationId, setApplicationId] = useState<string>("ALL");
  const [cursor, setCursor] = useState<string | undefined>(undefined);

  const applications = useQuery({
    queryKey: ["applications"],
    queryFn: () => api.applications.list({ limit: 100 }),
    enabled: can(Permission.APP_READ),
  });

  const appNameMap = useMemo(() => {
    const map = new Map<string, string>();
    for (const app of applications.data?.items ?? []) {
      map.set(app.id, app.name);
    }
    return map;
  }, [applications.data]);

  const findings = useQuery({
    queryKey: ["findings", statuses, search, applicationId, cursor ?? "first"],
    queryFn: () =>
      api.findings.list({
        limit: 50,
        status: statuses,
        ...(applicationId !== "ALL" ? { application_id: applicationId } : {}),
        ...(search ? { search } : {}),
        ...(cursor ? { cursor } : {}),
      }),
    enabled: can(Permission.FINDING_READ),
  });

  if (!can(Permission.FINDING_READ)) {
    return (
      <ErrorState error={new ApiError(403, null, "Your role does not include finding:read.")} />
    );
  }

  const toggleStatus = (status: string) => {
    setCursor(undefined);
    setStatuses((current) =>
      current.includes(status)
        ? current.filter((item) => item !== status)
        : [...current, status],
    );
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Findings"
        description="Vulnerabilities observed in running applications, worst first."
      />

      <Card>
        <CardContent className="flex flex-wrap items-center gap-2 p-4">
          {STATUS_FILTERS.map((status) => (
            <Button
              key={status}
              size="sm"
              variant={statuses.includes(status) ? "default" : "outline"}
              onClick={() => toggleStatus(status)}
              aria-pressed={statuses.includes(status)}
            >
              {status.replace("_", " ").toLowerCase()}
            </Button>
          ))}

          <div className="ml-auto flex items-center gap-2">
            <Select
              value={applicationId}
              onValueChange={(val) => {
                setCursor(undefined);
                setApplicationId(val);
              }}
            >
              <SelectTrigger className="w-56" aria-label="Filter by application">
                <SelectValue placeholder="All Applications" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ALL">All Applications</SelectItem>
                {applications.data?.items.map((app) => (
                  <SelectItem key={app.id} value={app.id}>
                    {app.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Input
              className="w-64"
              placeholder="Search titles…"
              value={search}
              onChange={(event) => {
                setCursor(undefined);
                setSearch(event.target.value);
              }}
              aria-label="Search findings"
            />
          </div>
        </CardContent>
      </Card>

      {findings.isLoading ? (
        <TableSkeleton rows={8} />
      ) : findings.isError ? (
        <ErrorState error={findings.error} onRetry={() => findings.refetch()} />
      ) : findings.data && findings.data.items.length === 0 ? (
        <EmptyState
          icon={<ShieldAlert className="size-8" />}
          title="Nothing here"
          description={
            statuses.length === 0
              ? "Choose at least one status to see findings."
              : "No findings match these filters. That is good news, or the agent has not seen traffic yet."
          }
        />
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Finding</TableHead>
                  <TableHead className="w-48">Application</TableHead>
                  <TableHead className="w-24">Risk</TableHead>
                  <TableHead className="w-28">Severity</TableHead>
                  <TableHead className="w-32">Status</TableHead>
                  <TableHead className="w-28">Seen</TableHead>
                  <TableHead className="w-32">Last seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {findings.data?.items.map((finding) => (
                  <TableRow key={finding.id}>
                    <TableCell>
                      <Link
                        href={`/findings/${finding.id}`}
                        className="font-medium hover:underline"
                      >
                        {finding.title}
                      </Link>
                      <p className="mt-0.5 text-xs text-muted-foreground">
                        {finding.route_templates[0] ?? finding.sink_signature}
                        {finding.cwe_id ? ` · CWE-${finding.cwe_id}` : ""}
                        {finding.regressed ? " · regressed" : ""}
                      </p>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="truncate max-w-[180px]">
                        {appNameMap.get(finding.application_id) ?? "Unknown App"}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono tabular-nums">
                      {finding.risk_score.toFixed(1)}
                    </TableCell>
                    <TableCell>
                      <Badge variant={severityVariant(finding.severity)}>{finding.severity}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant={findingStatusVariant(finding.status)}>
                        {finding.status.replace("_", " ")}
                      </Badge>
                    </TableCell>
                    <TableCell className="tabular-nums text-muted-foreground">
                      {finding.occurrence_count}×
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {relativeTime(finding.last_seen_at)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {findings.data?.page.next_cursor ? (
        <div className="flex justify-center">
          <Button variant="outline" onClick={() => setCursor(findings.data?.page.next_cursor ?? undefined)}>
            Load more
          </Button>
        </div>
      ) : null}
    </div>
  );
}
