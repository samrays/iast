"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Lock, Plus, ShieldCheck, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";

import { EmptyState, ErrorState, PageHeader } from "@/components/common";
import { Badge } from "@/components/ui/badge";
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/misc";
import { ApiError, api } from "@/lib/api-client";
import { useAuth } from "@/lib/auth-provider";
import { Permission } from "@/lib/permissions";
import type { PermissionCatalogueEntry, RoleSummary } from "@/lib/types";
import { describePermission } from "@/lib/utils";

export default function RolesPage() {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState<RoleSummary | "new" | null>(null);
  const [deleting, setDeleting] = useState<RoleSummary | null>(null);

  const roles = useQuery({
    queryKey: ["roles"],
    queryFn: () => api.organization.roles(),
    enabled: can(Permission.ORG_READ),
  });

  const catalogue = useQuery({
    queryKey: ["permission-catalogue"],
    queryFn: () => api.permissions.catalogue(),
  });

  const remove = useMutation({
    mutationFn: (roleId: string) => api.organization.deleteRole(roleId),
    onSuccess: () => {
      toast.success("Role deleted.");
      setDeleting(null);
      void queryClient.invalidateQueries({ queryKey: ["roles"] });
    },
    onError: (error) =>
      toast.error(error instanceof ApiError ? error.message : "Could not delete the role."),
  });

  if (!can(Permission.ORG_READ)) {
    return <ErrorState error={new ApiError(403, null, "Your role does not include org:read.")} />;
  }

  const systemRoles = (roles.data ?? []).filter((role) => role.is_system);
  const customRoles = (roles.data ?? []).filter((role) => !role.is_system);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Roles"
        description="Roles are bundles of permissions. Nothing in the platform authorizes on a role name — only on the permissions it carries."
        actions={
          can(Permission.ROLE_WRITE) ? (
            <Button onClick={() => setEditing("new")}>
              <Plus />
              Create role
            </Button>
          ) : null
        }
      />

      {roles.isLoading ? (
        <div className="grid gap-4 md:grid-cols-2">
          {Array.from({ length: 4 }).map((_, index) => (
            <Skeleton key={index} className="h-44 w-full" />
          ))}
        </div>
      ) : roles.isError ? (
        <ErrorState error={roles.error} onRetry={() => void roles.refetch()} />
      ) : (
        <>
          <section className="space-y-3">
            <h2 className="text-sm font-semibold text-muted-foreground">System roles</h2>
            <div className="grid gap-4 md:grid-cols-2">
              {systemRoles.map((role) => (
                <RoleCard key={role.id} role={role} />
              ))}
            </div>
          </section>

          <section className="space-y-3">
            <h2 className="text-sm font-semibold text-muted-foreground">Custom roles</h2>
            {customRoles.length === 0 ? (
              <Card>
                <CardContent className="p-0">
                  <EmptyState
                    icon={<ShieldCheck className="size-5" />}
                    title="No custom roles"
                    description="Create one when a team needs a permission set the system roles do not cover."
                    action={
                      can(Permission.ROLE_WRITE) ? (
                        <Button onClick={() => setEditing("new")}>
                          <Plus />
                          Create role
                        </Button>
                      ) : null
                    }
                  />
                </CardContent>
              </Card>
            ) : (
              <div className="grid gap-4 md:grid-cols-2">
                {customRoles.map((role) => (
                  <RoleCard
                    key={role.id}
                    role={role}
                    onEdit={can(Permission.ROLE_WRITE) ? () => setEditing(role) : undefined}
                    onDelete={can(Permission.ROLE_WRITE) ? () => setDeleting(role) : undefined}
                  />
                ))}
              </div>
            )}
          </section>
        </>
      )}

      <RoleDialog
        target={editing}
        catalogue={catalogue.data ?? []}
        onOpenChange={(open) => !open && setEditing(null)}
        onSaved={() => void queryClient.invalidateQueries({ queryKey: ["roles"] })}
      />

      <Dialog open={Boolean(deleting)} onOpenChange={(open) => !open && setDeleting(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Delete {deleting?.name}?</DialogTitle>
            <DialogDescription>
              A role still assigned to members cannot be deleted — reassign them first.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleting(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              loading={remove.isPending}
              onClick={() => deleting && remove.mutate(deleting.id)}
            >
              Delete role
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function RoleCard({
  role,
  onEdit,
  onDelete,
}: {
  role: RoleSummary;
  onEdit?: () => void;
  onDelete?: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const shown = expanded ? role.permissions : role.permissions.slice(0, 6);

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between gap-3">
        <div className="min-w-0">
          {/* The lock sits beside the heading, not inside it: an icon with a label inside
              an <h3> becomes part of the heading's accessible name, so screen readers and
              tests both see "Owner System role" instead of "Owner". */}
          <div className="flex items-center gap-2">
            <CardTitle className="text-base">{role.name}</CardTitle>
            {role.is_system ? (
              <span className="flex items-center gap-1 text-muted-foreground">
                <Lock className="size-3.5" aria-hidden />
                <span className="sr-only">System role</span>
              </span>
            ) : null}
          </div>
          <CardDescription>{role.description || "No description."}</CardDescription>
        </div>
        <div className="flex shrink-0 gap-1">
          {onEdit ? (
            <Button variant="outline" size="sm" onClick={onEdit}>
              Edit
            </Button>
          ) : null}
          {onDelete ? (
            <Button variant="ghost" size="icon-sm" aria-label={`Delete ${role.name}`} onClick={onDelete}>
              <Trash2 />
            </Button>
          ) : null}
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex flex-wrap gap-1">
          {shown.map((permission) => (
            <Badge key={permission} variant="secondary" className="font-mono normal-case">
              {permission}
            </Badge>
          ))}
          {role.permissions.length > 6 ? (
            <button
              type="button"
              onClick={() => setExpanded((value) => !value)}
              className="text-2xs font-medium text-primary hover:underline"
            >
              {expanded ? "show fewer" : `+${role.permissions.length - 6} more`}
            </button>
          ) : null}
        </div>
      </CardContent>
    </Card>
  );
}

function RoleDialog({
  target,
  catalogue,
  onOpenChange,
  onSaved,
}: {
  target: RoleSummary | "new" | null;
  catalogue: PermissionCatalogueEntry[];
  onOpenChange: (open: boolean) => void;
  onSaved: () => void;
}) {
  const { permissions: held } = useAuth();
  const isNew = target === "new";
  const role = target && target !== "new" ? target : null;

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [initialised, setInitialised] = useState<string | null>(null);

  const key = isNew ? "new" : (role?.id ?? null);
  if (target && initialised !== key) {
    setInitialised(key);
    setName(role?.name ?? "");
    setDescription(role?.description ?? "");
    setSelected(role?.permissions ?? []);
  }

  const grouped = useMemo(() => {
    const byResource = new Map<string, PermissionCatalogueEntry[]>();
    for (const entry of catalogue) {
      const list = byResource.get(entry.resource) ?? [];
      list.push(entry);
      byResource.set(entry.resource, list);
    }
    return [...byResource.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [catalogue]);

  const mutation = useMutation({
    mutationFn: () =>
      isNew
        ? api.organization.createRole({
            name: name.trim(),
            description: description.trim(),
            permissions: selected,
          })
        : api.organization.updateRole(role!.id, {
            name: name.trim(),
            description: description.trim(),
            permissions: selected,
          }),
    onSuccess: () => {
      toast.success(isNew ? "Role created." : "Role updated.");
      onOpenChange(false);
      onSaved();
    },
    onError: (error) =>
      toast.error(error instanceof ApiError ? error.message : "Could not save the role."),
  });

  return (
    <Dialog open={Boolean(target)} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{isNew ? "Create a role" : `Edit ${role?.name}`}</DialogTitle>
          <DialogDescription>
            You can only grant permissions you hold yourself — the ones beyond your own are
            disabled here and rejected by the API.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="role-name">Name</Label>
              <Input
                id="role-name"
                required
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="Release Manager"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="role-description">Description</Label>
              <Input
                id="role-description"
                value={description}
                onChange={(event) => setDescription(event.target.value)}
                placeholder="What this role is for"
              />
            </div>
          </div>

          <div className="space-y-3">
            <Label>Permissions ({selected.length} selected)</Label>
            <div className="max-h-72 space-y-4 overflow-y-auto rounded-md border border-border p-3">
              {grouped.map(([resource, entries]) => (
                <div key={resource}>
                  <p className="mb-1.5 text-2xs font-semibold uppercase tracking-wide text-muted-foreground">
                    {resource}
                  </p>
                  <div className="grid gap-1 sm:grid-cols-2">
                    {entries.map((entry) => {
                      const beyondReach = !held.includes(entry.value);
                      return (
                        <label
                          key={entry.value}
                          className={`flex items-center gap-2 rounded px-2 py-1 text-sm ${
                            beyondReach
                              ? "cursor-not-allowed opacity-50"
                              : "cursor-pointer hover:bg-accent/40"
                          }`}
                        >
                          <input
                            type="checkbox"
                            className="size-4 accent-[hsl(var(--primary))]"
                            checked={selected.includes(entry.value)}
                            disabled={beyondReach}
                            onChange={() =>
                              setSelected((current) =>
                                current.includes(entry.value)
                                  ? current.filter((item) => item !== entry.value)
                                  : [...current, entry.value],
                              )
                            }
                          />
                          <span className="min-w-0 flex-1 truncate">
                            {describePermission(entry.value)}
                          </span>
                          {entry.privileged ? <Badge variant="medium">priv</Badge> : null}
                        </label>
                      );
                    })}
                  </div>
                </div>
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
            {isNew ? "Create role" : "Save changes"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
