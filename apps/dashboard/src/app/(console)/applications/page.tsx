"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { Boxes, Plus, Search } from "lucide-react";
import { useState, type FormEvent } from "react";
import { toast } from "sonner";

import { EmptyState, ErrorState, PageHeader, TableSkeleton } from "@/components/common";
import { Badge, criticalityVariant, protectionVariant } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/misc";
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
  CRITICALITIES,
  ENVIRONMENT_KINDS,
  LANGUAGES,
  type Criticality,
  type EnvironmentKind,
  type Language,
} from "@/lib/types";
import { relativeTime } from "@/lib/utils";

export default function ApplicationsPage() {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [submittedSearch, setSubmittedSearch] = useState("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [createOpen, setCreateOpen] = useState(false);

  const applications = useQuery({
    queryKey: ["applications", submittedSearch, cursor ?? "first"],
    queryFn: () =>
      api.applications.list({ limit: 25, ...(submittedSearch ? { q: submittedSearch } : {}), ...(cursor ? { cursor } : {}) }),
    enabled: can(Permission.APP_READ),
  });

  const onSearch = (event: FormEvent) => {
    event.preventDefault();
    setCursor(undefined);
    setSubmittedSearch(search.trim());
  };

  if (!can(Permission.APP_READ)) {
    return (
      <ErrorState
        error={new ApiError(403, null, "Your role does not include app:read.")}
      />
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Applications"
        description="Every service under test, with the environments an agent can report from."
        actions={
          can(Permission.APP_WRITE) ? (
            <Button onClick={() => setCreateOpen(true)}>
              <Plus />
              Register application
            </Button>
          ) : null
        }
      />

      <form onSubmit={onSearch} className="flex max-w-md items-center gap-2">
        <div className="relative flex-1">
          <Search
            className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search by name or slug"
            aria-label="Search applications"
            className="pl-9"
          />
        </div>
        <Button type="submit" variant="outline">
          Search
        </Button>
      </form>

      <Card>
        <CardContent className="p-0">
          {applications.isLoading ? (
            <TableSkeleton rows={6} columns={5} />
          ) : applications.isError ? (
            <ErrorState error={applications.error} onRetry={() => void applications.refetch()} />
          ) : applications.data && applications.data.items.length === 0 ? (
            <EmptyState
              icon={<Boxes className="size-5" />}
              title={submittedSearch ? "No applications match that search" : "No applications yet"}
              description={
                submittedSearch
                  ? "Try a different term, or clear the search."
                  : "Register one here, or let an agent discover it on first registration."
              }
              action={
                can(Permission.APP_WRITE) && !submittedSearch ? (
                  <Button onClick={() => setCreateOpen(true)}>
                    <Plus />
                    Register application
                  </Button>
                ) : null
              }
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Application</TableHead>
                  <TableHead>Language</TableHead>
                  <TableHead>Criticality</TableHead>
                  <TableHead>Environments</TableHead>
                  <TableHead>Registered</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {applications.data?.items.map((application) => (
                  <TableRow key={application.id}>
                    <TableCell>
                      <Link
                        href={`/applications/${application.id}`}
                        className="font-medium transition-colors hover:text-primary"
                      >
                        {application.name}
                      </Link>
                      <p className="font-mono text-2xs text-muted-foreground">{application.slug}</p>
                      {application.tags.length > 0 ? (
                        <div className="mt-1 flex flex-wrap gap-1">
                          {application.tags.map((tag) => (
                            <Badge key={tag} variant="outline">
                              {tag}
                            </Badge>
                          ))}
                        </div>
                      ) : null}
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-xs">{application.language}</span>
                    </TableCell>
                    <TableCell>
                      <Badge variant={criticalityVariant(application.criticality)}>
                        {application.criticality}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {application.environments.length === 0 ? (
                          <span className="text-xs text-muted-foreground">none</span>
                        ) : (
                          application.environments.map((environment) => (
                            <Badge
                              key={environment.id}
                              variant={protectionVariant(environment.protection_mode)}
                              title={`${environment.kind} · ${environment.protection_mode}`}
                            >
                              {environment.kind.slice(0, 4)}
                            </Badge>
                          ))
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                      {relativeTime(application.created_at)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {applications.data?.page.has_more || cursor ? (
        <div className="flex items-center justify-between">
          <Button variant="outline" size="sm" disabled={!cursor} onClick={() => setCursor(undefined)}>
            First page
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={!applications.data?.page.has_more}
            onClick={() => setCursor(applications.data?.page.next_cursor ?? undefined)}
          >
            Next page
          </Button>
        </div>
      ) : null}

      <CreateApplicationDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={() => {
          setCursor(undefined);
          void queryClient.invalidateQueries({ queryKey: ["applications"] });
        }}
      />
    </div>
  );
}

function CreateApplicationDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: () => void;
}) {
  const [name, setName] = useState("");
  const [language, setLanguage] = useState<Language>("JAVA");
  const [criticality, setCriticality] = useState<Criticality>("MEDIUM");
  const [tags, setTags] = useState("");
  const [repositoryUrl, setRepositoryUrl] = useState("");
  const [description, setDescription] = useState("");
  const [environmentKind, setEnvironmentKind] = useState<EnvironmentKind>("PRODUCTION");
  const [internetFacing, setInternetFacing] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  const reset = () => {
    setName("");
    setTags("");
    setRepositoryUrl("");
    setDescription("");
    setFieldErrors({});
  };

  const mutation = useMutation({
    mutationFn: () =>
      api.applications.create({
        name: name.trim(),
        language,
        criticality,
        tags: tags
          .split(",")
          .map((tag) => tag.trim().toLowerCase())
          .filter(Boolean),
        repository_url: repositoryUrl.trim() || null,
        description: description.trim(),
        environments: [{ kind: environmentKind, internet_facing: internetFacing }],
      }),
    onSuccess: (application) => {
      toast.success(`${application.name} registered.`);
      reset();
      onOpenChange(false);
      onCreated();
    },
    onError: (error) => {
      if (error instanceof ApiError) {
        setFieldErrors(error.fieldErrors);
        toast.error(error.message);
        return;
      }
      toast.error("Could not register the application.");
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Register an application</DialogTitle>
          <DialogDescription>
            An agent can also register an application on first connection. Doing it here
            lets you set criticality and tags in advance.
          </DialogDescription>
        </DialogHeader>

        <form
          id="create-application"
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault();
            mutation.mutate();
          }}
        >
          <div className="space-y-2">
            <Label htmlFor="app-name">Name</Label>
            <Input
              id="app-name"
              required
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="Payments API"
              aria-invalid={Boolean(fieldErrors.name)}
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="app-language">Runtime</Label>
              <Select value={language} onValueChange={(value) => setLanguage(value as Language)}>
                <SelectTrigger id="app-language">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {LANGUAGES.map((item) => (
                    <SelectItem key={item} value={item}>
                      {item}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="app-criticality">Criticality</Label>
              <Select
                value={criticality}
                onValueChange={(value) => setCriticality(value as Criticality)}
              >
                <SelectTrigger id="app-criticality">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CRITICALITIES.map((item) => (
                    <SelectItem key={item} value={item}>
                      {item}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="app-tags">Tags</Label>
            <Input
              id="app-tags"
              value={tags}
              onChange={(event) => setTags(event.target.value)}
              placeholder="pci, payments"
              aria-invalid={Boolean(fieldErrors.tags)}
            />
            {fieldErrors.tags ? (
              <p className="text-xs text-destructive">{fieldErrors.tags}</p>
            ) : (
              <p className="text-xs text-muted-foreground">
                Comma separated. Lowercase alphanumerics, dot, dash or underscore.
              </p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="app-repo">Repository URL</Label>
            <Input
              id="app-repo"
              type="url"
              value={repositoryUrl}
              onChange={(event) => setRepositoryUrl(event.target.value)}
              placeholder="https://github.com/acme/payments-api"
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="app-env">First environment</Label>
              <Select
                value={environmentKind}
                onValueChange={(value) => setEnvironmentKind(value as EnvironmentKind)}
              >
                <SelectTrigger id="app-env">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ENVIRONMENT_KINDS.map((item) => (
                    <SelectItem key={item} value={item}>
                      {item}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-end gap-3 pb-1">
              <Switch
                id="app-internet"
                checked={internetFacing}
                onCheckedChange={setInternetFacing}
              />
              <Label htmlFor="app-internet" className="cursor-pointer">
                Internet facing
              </Label>
            </div>
          </div>
        </form>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} type="button">
            Cancel
          </Button>
          <Button type="submit" form="create-application" loading={mutation.isPending}>
            Register
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
