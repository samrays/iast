"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Plus, TriangleAlert, X } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";

import { CopyButton, EmptyState, ErrorState, PageHeader, TableSkeleton } from "@/components/common";
import { Badge } from "@/components/ui/badge";
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
import type { ApiKeySummary } from "@/lib/types";
import { absoluteTime, describePermission, relativeTime } from "@/lib/utils";

const EXPIRY_OPTIONS = [
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
  { value: "180", label: "180 days" },
  { value: "365", label: "1 year" },
  { value: "never", label: "No expiry" },
];

export default function ApiKeysPage() {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [issued, setIssued] = useState<{ secret: string; name: string } | null>(null);
  const [revoking, setRevoking] = useState<ApiKeySummary | null>(null);

  const keys = useQuery({
    queryKey: ["api-keys"],
    queryFn: () => api.apiKeys.list(),
    enabled: can(Permission.SETTINGS_WRITE),
  });

  const revoke = useMutation({
    mutationFn: (id: string) => api.apiKeys.revoke(id),
    onSuccess: () => {
      toast.success("Key revoked. It stops working on the next request.");
      setRevoking(null);
      void queryClient.invalidateQueries({ queryKey: ["api-keys"] });
    },
    onError: (error) =>
      toast.error(error instanceof ApiError ? error.message : "Could not revoke the key."),
  });

  if (!can(Permission.SETTINGS_WRITE)) {
    return (
      <ErrorState error={new ApiError(403, null, "Your role does not include settings:write.")} />
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="API keys"
        description="Credentials for CI pipelines and agent bootstrap. A key can never carry a permission you do not hold yourself."
        actions={
          <Button onClick={() => setCreateOpen(true)}>
            <Plus />
            Issue key
          </Button>
        }
      />

      <Card>
        <CardContent className="p-0">
          {keys.isLoading ? (
            <TableSkeleton rows={4} columns={5} />
          ) : keys.isError ? (
            <ErrorState error={keys.error} onRetry={() => void keys.refetch()} />
          ) : (keys.data?.length ?? 0) === 0 ? (
            <EmptyState
              icon={<KeyRound className="size-5" />}
              title="No API keys"
              description="Agents register with a key holding agent:write. CI uses one scoped to what the pipeline actually needs."
              action={
                <Button onClick={() => setCreateOpen(true)}>
                  <Plus />
                  Issue key
                </Button>
              }
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Prefix</TableHead>
                  <TableHead>Permissions</TableHead>
                  <TableHead>Last used</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {keys.data?.map((key) => (
                  <TableRow key={key.id} className={key.is_active ? undefined : "opacity-60"}>
                    <TableCell>
                      <span className="font-medium">{key.name}</span>
                      {!key.is_active ? (
                        <Badge variant="outline" className="ml-2">
                          revoked
                        </Badge>
                      ) : null}
                    </TableCell>
                    <TableCell className="font-mono text-xs">ak_{key.prefix}…</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {key.permissions.slice(0, 3).map((permission) => (
                          <Badge key={permission} variant="secondary" className="font-mono normal-case">
                            {permission}
                          </Badge>
                        ))}
                        {key.permissions.length > 3 ? (
                          <Badge variant="outline">+{key.permissions.length - 3}</Badge>
                        ) : null}
                      </div>
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                      {key.last_used_at ? relativeTime(key.last_used_at) : "never used"}
                    </TableCell>
                    <TableCell
                      className="whitespace-nowrap text-xs text-muted-foreground"
                      title={key.expires_at ? absoluteTime(key.expires_at) : undefined}
                    >
                      {key.expires_at ? relativeTime(key.expires_at).replace(" ago", "") : "never"}
                    </TableCell>
                    <TableCell className="text-right">
                      {key.is_active ? (
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          aria-label={`Revoke ${key.name}`}
                          onClick={() => setRevoking(key)}
                        >
                          <X />
                        </Button>
                      ) : null}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <CreateKeyDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onIssued={(secret, name) => {
          setIssued({ secret, name });
          void queryClient.invalidateQueries({ queryKey: ["api-keys"] });
        }}
      />

      <Dialog open={Boolean(issued)} onOpenChange={(open) => !open && setIssued(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Copy your key now</DialogTitle>
            <DialogDescription>
              Only a hash is stored. There is no endpoint that can show this value again —
              if you lose it, issue a new key.
            </DialogDescription>
          </DialogHeader>
          <div className="flex items-start gap-2 rounded-md border border-severity-medium/40 bg-severity-medium-surface p-3">
            <TriangleAlert className="mt-0.5 size-4 shrink-0 text-severity-medium" aria-hidden />
            <p className="text-xs text-severity-medium">
              Treat this like a password. Anyone holding it can act as{" "}
              <strong>{issued?.name}</strong> against your organization.
            </p>
          </div>
          <pre className="overflow-x-auto rounded-md border border-border bg-muted p-3 font-mono text-xs">
            {issued?.secret}
          </pre>
          <DialogFooter>
            {issued ? <CopyButton value={issued.secret} label="Copy key" /> : null}
            <Button onClick={() => setIssued(null)}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(revoking)} onOpenChange={(open) => !open && setRevoking(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Revoke {revoking?.name}?</DialogTitle>
            <DialogDescription>
              Anything using this key — a CI job, an agent bootstrap — starts failing
              immediately. Agents already registered keep their own credentials.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRevoking(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              loading={revoke.isPending}
              onClick={() => revoking && revoke.mutate(revoking.id)}
            >
              Revoke key
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function CreateKeyDialog({
  open,
  onOpenChange,
  onIssued,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onIssued: (secret: string, name: string) => void;
}) {
  const { permissions: held } = useAuth();
  const [name, setName] = useState("");
  const [expiry, setExpiry] = useState("90");
  const [selected, setSelected] = useState<string[]>([]);

  const catalogue = useQuery({
    queryKey: ["permission-catalogue"],
    queryFn: () => api.permissions.catalogue(),
    enabled: open,
  });

  // Only offer what the issuer actually holds; the API rejects the rest with 403.
  const grantable = useMemo(
    () => (catalogue.data ?? []).filter((entry) => held.includes(entry.value)),
    [catalogue.data, held],
  );

  const mutation = useMutation({
    mutationFn: () =>
      api.apiKeys.create({
        name: name.trim(),
        permissions: selected,
        expires_in_days: expiry === "never" ? null : Number(expiry),
      }),
    onSuccess: (result) => {
      onIssued(result.secret, result.api_key.name);
      setName("");
      setSelected([]);
      onOpenChange(false);
    },
    onError: (error) =>
      toast.error(error instanceof ApiError ? error.message : "Could not issue the key."),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>Issue an API key</DialogTitle>
          <DialogDescription>
            Grant only what the consumer needs. An agent bootstrap needs agent:write and
            nothing else.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="key-name">Name</Label>
              <Input
                id="key-name"
                required
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="ci-pipeline"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="key-expiry">Expires</Label>
              <Select value={expiry} onValueChange={setExpiry}>
                <SelectTrigger id="key-expiry">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {EXPIRY_OPTIONS.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-2">
            <Label>Permissions ({selected.length} selected)</Label>
            <div className="grid max-h-64 gap-1 overflow-y-auto rounded-md border border-border p-3 sm:grid-cols-2">
              {grantable.map((entry) => (
                <label
                  key={entry.value}
                  className="flex cursor-pointer items-center gap-2 rounded px-2 py-1 text-sm hover:bg-accent/40"
                >
                  <input
                    type="checkbox"
                    className="size-4 accent-[hsl(var(--primary))]"
                    checked={selected.includes(entry.value)}
                    onChange={() =>
                      setSelected((current) =>
                        current.includes(entry.value)
                          ? current.filter((item) => item !== entry.value)
                          : [...current, entry.value],
                      )
                    }
                  />
                  <span className="min-w-0 flex-1 truncate">{describePermission(entry.value)}</span>
                  <span className="shrink-0 font-mono text-2xs text-muted-foreground">
                    {entry.value}
                  </span>
                </label>
              ))}
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            loading={mutation.isPending}
            disabled={!name.trim() || selected.length === 0}
            onClick={() => mutation.mutate()}
          >
            Issue key
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
