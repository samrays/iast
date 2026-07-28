"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { ArrowLeft, ExternalLink, Plus, ShieldCheck, Trash2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { DetailList, EmptyState, ErrorState, PageHeader } from "@/components/common";
import {
  Badge,
  agentStatusVariant,
  criticalityVariant,
  protectionVariant,
} from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Skeleton, Switch } from "@/components/ui/misc";
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
import {
  ENVIRONMENT_KINDS,
  PROTECTION_MODES,
  type EnvironmentKind,
  type ProtectionMode,
} from "@/lib/types";
import { absoluteTime, relativeTime } from "@/lib/utils";

export default function ApplicationDetailPage() {
  const params = useParams<{ id: string }>();
  const applicationId = params.id;
  const router = useRouter();
  const queryClient = useQueryClient();
  const { can } = useAuth();
  const [addEnvOpen, setAddEnvOpen] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const application = useQuery({
    queryKey: ["application", applicationId],
    queryFn: () => api.applications.get(applicationId),
    enabled: can(Permission.APP_READ),
  });

  const agents = useQuery({
    queryKey: ["agents", "for-application", applicationId],
    queryFn: () => api.agents.list({ limit: 200 }),
    enabled: can(Permission.AGENT_READ),
    select: (page) => page.items,
  });

  const setProtection = useMutation({
    mutationFn: ({ environmentId, mode }: { environmentId: string; mode: ProtectionMode }) =>
      api.environments.setProtection(environmentId, mode),
    onSuccess: (environment) => {
      toast.success(`${environment.kind} set to ${environment.protection_mode}.`);
      void queryClient.invalidateQueries({ queryKey: ["application", applicationId] });
    },
    onError: (error) => {
      // The API refuses BLOCK in production without a completed monitor soak, and refuses
      // it entirely on a licence without protection. Both are worth showing verbatim.
      toast.error(error instanceof ApiError ? error.message : "Could not change protection mode.");
    },
  });

  const remove = useMutation({
    mutationFn: () => api.applications.remove(applicationId),
    onSuccess: () => {
      toast.success("Application deleted.");
      void queryClient.invalidateQueries({ queryKey: ["applications"] });
      router.push("/applications");
    },
    onError: (error) =>
      toast.error(error instanceof ApiError ? error.message : "Could not delete the application."),
  });

  if (!can(Permission.APP_READ)) {
    return <ErrorState error={new ApiError(403, null, "Your role does not include app:read.")} />;
  }

  if (application.isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-9 w-64" />
        <Skeleton className="h-40 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (application.isError || !application.data) {
    return <ErrorState error={application.error} onRetry={() => void application.refetch()} />;
  }

  const app = application.data;
  const environmentIds = new Set(app.environments.map((environment) => environment.id));
  const applicationAgents = (agents.data ?? []).filter((agent) =>
    environmentIds.has(agent.application_environment_id),
  );

  return (
    <div className="space-y-6">
      <Button variant="ghost" size="sm" asChild className="-ml-2">
        <Link href="/applications">
          <ArrowLeft />
          All applications
        </Link>
      </Button>

      <PageHeader
        title={app.name}
        description={app.description || "No description recorded."}
        actions={
          <div className="flex items-center gap-2">
            <Badge variant={criticalityVariant(app.criticality)}>{app.criticality}</Badge>
            {can(Permission.APP_DELETE) ? (
              <Button variant="outline" size="sm" onClick={() => setConfirmDelete(true)}>
                <Trash2 />
                Delete
              </Button>
            ) : null}
          </div>
        }
      />

      <Card>
        <CardContent className="p-5">
          <DetailList
            items={[
              { label: "Slug", value: <span className="font-mono text-xs">{app.slug}</span> },
              { label: "Runtime", value: app.language },
              {
                label: "Tags",
                value:
                  app.tags.length === 0 ? (
                    <span className="text-muted-foreground">none</span>
                  ) : (
                    <span className="flex flex-wrap gap-1">
                      {app.tags.map((tag) => (
                        <Badge key={tag} variant="outline">
                          {tag}
                        </Badge>
                      ))}
                    </span>
                  ),
              },
              {
                label: "Repository",
                value: app.repository_url ? (
                  <a
                    href={app.repository_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-primary hover:underline"
                  >
                    {app.repository_url.replace(/^https?:\/\//, "")}
                    <ExternalLink className="size-3" />
                  </a>
                ) : (
                  <span className="text-muted-foreground">not linked</span>
                ),
              },
              { label: "Registered", value: absoluteTime(app.created_at) },
              {
                label: "Coverage",
                value:
                  applicationAgents.length === 0 ? (
                    <span className="text-severity-critical">
                      No agent has ever reported — treat as unobserved
                    </span>
                  ) : (
                    `${applicationAgents.length} agent(s) reporting`
                  ),
              },
            ]}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex-row items-start justify-between gap-4">
          <div>
            <CardTitle className="text-base">Environments</CardTitle>
            <CardDescription>
              Protection mode governs what an agent does when it confirms an exploit.
              Production cannot jump straight to blocking.
            </CardDescription>
          </div>
          {can(Permission.APP_WRITE) ? (
            <Button variant="outline" size="sm" onClick={() => setAddEnvOpen(true)}>
              <Plus />
              Add
            </Button>
          ) : null}
        </CardHeader>
        <CardContent className="p-0">
          {app.environments.length === 0 ? (
            <EmptyState
              title="No environments"
              description="Add one, or let an agent create it on first registration."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Environment</TableHead>
                  <TableHead>Exposure</TableHead>
                  <TableHead>Protection</TableHead>
                  <TableHead>Agents</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {app.environments.map((environment) => {
                  const environmentAgents = applicationAgents.filter(
                    (agent) => agent.application_environment_id === environment.id,
                  );
                  return (
                    <TableRow key={environment.id}>
                      <TableCell className="font-medium">{environment.kind}</TableCell>
                      <TableCell>
                        {environment.internet_facing ? (
                          <Badge variant="high">Internet facing</Badge>
                        ) : (
                          <Badge variant="outline">Internal</Badge>
                        )}
                      </TableCell>
                      <TableCell>
                        {can(Permission.POLICY_WRITE) ? (
                          <Select
                            value={environment.protection_mode}
                            onValueChange={(value) =>
                              setProtection.mutate({
                                environmentId: environment.id,
                                mode: value as ProtectionMode,
                              })
                            }
                          >
                            <SelectTrigger className="h-8 w-36" aria-label="Protection mode">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              {PROTECTION_MODES.map((mode) => (
                                <SelectItem key={mode} value={mode}>
                                  {mode}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        ) : (
                          <Badge variant={protectionVariant(environment.protection_mode)}>
                            {environment.protection_mode}
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell>
                        {environmentAgents.length === 0 ? (
                          <span className="text-xs text-muted-foreground">none</span>
                        ) : (
                          <div className="flex flex-wrap gap-1">
                            {environmentAgents.map((agent) => (
                              <Badge key={agent.id} variant={agentStatusVariant(agent.status)}>
                                {agent.hostname}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Agents</CardTitle>
          <CardDescription>Runtime processes reporting for this application.</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {!can(Permission.AGENT_READ) ? (
            <EmptyState title="Agent access required" description="Your role lacks agent:read." />
          ) : applicationAgents.length === 0 ? (
            <EmptyState
              icon={<ShieldCheck className="size-5" />}
              title="No agents yet"
              description="Register an agent with an API key holding agent:write, pointing at this application name."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Host</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead>Overhead</TableHead>
                  <TableHead>Last seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {applicationAgents.map((agent) => (
                  <TableRow key={agent.id}>
                    <TableCell className="font-medium">{agent.hostname}</TableCell>
                    <TableCell>
                      <Badge variant={agentStatusVariant(agent.status)}>{agent.status}</Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs">{agent.agent_version}</TableCell>
                    <TableCell className="tabular-nums text-xs">
                      {agent.cpu_overhead_pct === null ? "—" : `${agent.cpu_overhead_pct}%`}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                      {relativeTime(agent.last_seen_at)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <AddEnvironmentDialog
        applicationId={applicationId}
        existing={app.environments.map((environment) => environment.kind)}
        open={addEnvOpen}
        onOpenChange={setAddEnvOpen}
      />

      <Dialog open={confirmDelete} onOpenChange={setConfirmDelete}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Delete {app.name}?</DialogTitle>
            <DialogDescription>
              This removes the application, its environments and its registered agents. The
              audit entry recording the deletion is permanent.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmDelete(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              loading={remove.isPending}
              onClick={() => remove.mutate()}
            >
              Delete permanently
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function AddEnvironmentDialog({
  applicationId,
  existing,
  open,
  onOpenChange,
}: {
  applicationId: string;
  existing: EnvironmentKind[];
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const queryClient = useQueryClient();
  const available = ENVIRONMENT_KINDS.filter((kind) => !existing.includes(kind));
  const [kind, setKind] = useState<EnvironmentKind>(available[0] ?? "PRODUCTION");
  const [internetFacing, setInternetFacing] = useState(false);

  const mutation = useMutation({
    mutationFn: () =>
      api.applications.addEnvironment(applicationId, { kind, internet_facing: internetFacing }),
    onSuccess: () => {
      toast.success(`${kind} environment added.`);
      onOpenChange(false);
      void queryClient.invalidateQueries({ queryKey: ["application", applicationId] });
    },
    onError: (error) =>
      toast.error(error instanceof ApiError ? error.message : "Could not add the environment."),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Add an environment</DialogTitle>
          <DialogDescription>
            Each application may hold one environment of each kind.
          </DialogDescription>
        </DialogHeader>

        {available.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Every environment kind already exists for this application.
          </p>
        ) : (
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="env-kind">Kind</Label>
              <Select value={kind} onValueChange={(value) => setKind(value as EnvironmentKind)}>
                <SelectTrigger id="env-kind">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {available.map((item) => (
                    <SelectItem key={item} value={item}>
                      {item}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center gap-3">
              <Switch
                id="env-internet"
                checked={internetFacing}
                onCheckedChange={setInternetFacing}
              />
              <Label htmlFor="env-internet" className="cursor-pointer">
                Internet facing
              </Label>
            </div>
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            disabled={available.length === 0}
            loading={mutation.isPending}
            onClick={() => mutation.mutate()}
          >
            Add environment
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
