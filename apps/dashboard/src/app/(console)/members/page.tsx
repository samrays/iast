"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { UserPlus, Users, X } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { EmptyState, ErrorState, PageHeader, TableSkeleton } from "@/components/common";
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
import type { MemberSummary, RoleSummary } from "@/lib/types";
import { initials, relativeTime } from "@/lib/utils";

export default function MembersPage() {
  const { can, principal } = useAuth();
  const queryClient = useQueryClient();
  const [inviteOpen, setInviteOpen] = useState(false);
  const [editing, setEditing] = useState<MemberSummary | null>(null);
  const [removing, setRemoving] = useState<MemberSummary | null>(null);

  const members = useQuery({
    queryKey: ["members"],
    queryFn: () => api.organization.members({ limit: 100 }),
    enabled: can(Permission.ORG_READ),
  });

  const roles = useQuery({
    queryKey: ["roles"],
    queryFn: () => api.organization.roles(),
    enabled: can(Permission.ORG_READ),
  });

  const remove = useMutation({
    mutationFn: (membershipId: string) => api.organization.removeMember(membershipId),
    onSuccess: () => {
      toast.success("Member removed. Their live sessions were revoked immediately.");
      setRemoving(null);
      void queryClient.invalidateQueries({ queryKey: ["members"] });
    },
    onError: (error) =>
      toast.error(error instanceof ApiError ? error.message : "Could not remove the member."),
  });

  if (!can(Permission.ORG_READ)) {
    return <ErrorState error={new ApiError(403, null, "Your role does not include org:read.")} />;
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Members"
        description="Who belongs to this organization, and what their roles let them do."
        actions={
          can(Permission.USER_INVITE) ? (
            <Button onClick={() => setInviteOpen(true)}>
              <UserPlus />
              Invite member
            </Button>
          ) : null
        }
      />

      <Card>
        <CardContent className="p-0">
          {members.isLoading ? (
            <TableSkeleton rows={5} columns={5} />
          ) : members.isError ? (
            <ErrorState error={members.error} onRetry={() => void members.refetch()} />
          ) : (members.data?.items.length ?? 0) === 0 ? (
            <EmptyState icon={<Users className="size-5" />} title="No members" />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Person</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Roles</TableHead>
                  <TableHead>Last sign-in</TableHead>
                  {can(Permission.ROLE_WRITE) || can(Permission.USER_REMOVE) ? <TableHead /> : null}
                </TableRow>
              </TableHeader>
              <TableBody>
                {members.data?.items.map((member) => (
                  <TableRow key={member.membership_id}>
                    <TableCell>
                      <div className="flex items-center gap-3">
                        <span className="flex size-8 shrink-0 items-center justify-center rounded-full bg-primary/10 text-2xs font-semibold text-primary">
                          {initials(member.full_name, member.email)}
                        </span>
                        <div className="min-w-0">
                          <p className="truncate font-medium">
                            {member.full_name || "—"}
                            {member.user_id === principal?.user_id ? (
                              <span className="ml-2 text-2xs text-muted-foreground">you</span>
                            ) : null}
                          </p>
                          <p className="truncate text-xs text-muted-foreground">{member.email}</p>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant={member.status === "ACTIVE" ? "online" : "outline"}>
                        {member.status}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {member.roles.map((role) => (
                          <Badge key={role.id} variant={role.is_system ? "default" : "secondary"}>
                            {role.name}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                      {relativeTime(member.last_login_at)}
                    </TableCell>
                    {can(Permission.ROLE_WRITE) || can(Permission.USER_REMOVE) ? (
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-2">
                          {can(Permission.ROLE_WRITE) ? (
                            <Button variant="outline" size="sm" onClick={() => setEditing(member)}>
                              Change roles
                            </Button>
                          ) : null}
                          {can(Permission.USER_REMOVE) &&
                          member.user_id !== principal?.user_id ? (
                            <Button
                              variant="ghost"
                              size="icon-sm"
                              aria-label={`Remove ${member.email}`}
                              onClick={() => setRemoving(member)}
                            >
                              <X />
                            </Button>
                          ) : null}
                        </div>
                      </TableCell>
                    ) : null}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <InviteDialog
        open={inviteOpen}
        onOpenChange={setInviteOpen}
        roles={roles.data ?? []}
        onInvited={() => void queryClient.invalidateQueries({ queryKey: ["members"] })}
      />

      <EditRolesDialog
        member={editing}
        roles={roles.data ?? []}
        onOpenChange={(open) => !open && setEditing(null)}
        onSaved={() => void queryClient.invalidateQueries({ queryKey: ["members"] })}
      />

      <Dialog open={Boolean(removing)} onOpenChange={(open) => !open && setRemoving(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Remove {removing?.email}?</DialogTitle>
            <DialogDescription>
              They lose access immediately — every live session in this organization is
              revoked, not just future ones.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRemoving(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              loading={remove.isPending}
              onClick={() => removing && remove.mutate(removing.membership_id)}
            >
              Remove member
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function RolePicker({
  roles,
  selected,
  onToggle,
  heldPermissions,
}: {
  roles: RoleSummary[];
  selected: string[];
  onToggle: (roleId: string) => void;
  heldPermissions: string[];
}) {
  return (
    <div className="space-y-2">
      {roles.map((role) => {
        // A member can only grant permissions they hold themselves; the API enforces this
        // and returns 403 privilege_escalation. Marking it here saves a pointless attempt.
        const beyondReach = role.permissions.filter(
          (permission) => !heldPermissions.includes(permission),
        );
        const disabled = beyondReach.length > 0;
        return (
          <label
            key={role.id}
            className={`flex cursor-pointer items-start gap-3 rounded-md border p-3 transition-colors ${
              selected.includes(role.id) ? "border-primary bg-accent/50" : "border-border"
            } ${disabled ? "cursor-not-allowed opacity-60" : "hover:bg-accent/30"}`}
          >
            <input
              type="checkbox"
              className="mt-0.5 size-4 accent-[hsl(var(--primary))]"
              checked={selected.includes(role.id)}
              disabled={disabled}
              onChange={() => onToggle(role.id)}
            />
            <span className="min-w-0 flex-1">
              <span className="flex items-center gap-2">
                <span className="text-sm font-medium">{role.name}</span>
                {role.is_system ? <Badge variant="outline">system</Badge> : null}
              </span>
              <span className="mt-0.5 block text-xs text-muted-foreground">
                {role.description || `${role.permissions.length} permissions`}
              </span>
              {disabled ? (
                <span className="mt-1 block text-2xs text-severity-medium">
                  You cannot grant this role — it includes {beyondReach.slice(0, 2).join(", ")}
                  {beyondReach.length > 2 ? ` and ${beyondReach.length - 2} more` : ""}.
                </span>
              ) : null}
            </span>
          </label>
        );
      })}
    </div>
  );
}

function InviteDialog({
  open,
  onOpenChange,
  roles,
  onInvited,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  roles: RoleSummary[];
  onInvited: () => void;
}) {
  const { permissions } = useAuth();
  const [email, setEmail] = useState("");
  const [fullName, setFullName] = useState("");
  const [selected, setSelected] = useState<string[]>([]);

  const mutation = useMutation({
    mutationFn: () =>
      api.organization.invite({ email: email.trim(), full_name: fullName.trim(), role_ids: selected }),
    onSuccess: () => {
      toast.success(`${email} invited.`);
      setEmail("");
      setFullName("");
      setSelected([]);
      onOpenChange(false);
      onInvited();
    },
    onError: (error) =>
      toast.error(error instanceof ApiError ? error.message : "Could not send the invitation."),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Invite a member</DialogTitle>
          <DialogDescription>
            They join with the roles you pick here. Until they set a password their
            membership stays in the invited state.
          </DialogDescription>
        </DialogHeader>

        <form
          id="invite-member"
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault();
            mutation.mutate();
          }}
        >
          <div className="space-y-2">
            <Label htmlFor="invite-email">Email</Label>
            <Input
              id="invite-email"
              type="email"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="analyst@example.com"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="invite-name">Full name</Label>
            <Input
              id="invite-name"
              value={fullName}
              onChange={(event) => setFullName(event.target.value)}
              placeholder="Ada Lovelace"
            />
          </div>
          <div className="space-y-2">
            <Label>Roles</Label>
            <RolePicker
              roles={roles}
              selected={selected}
              heldPermissions={permissions}
              onToggle={(roleId) =>
                setSelected((current) =>
                  current.includes(roleId)
                    ? current.filter((id) => id !== roleId)
                    : [...current, roleId],
                )
              }
            />
          </div>
        </form>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            type="submit"
            form="invite-member"
            loading={mutation.isPending}
            disabled={selected.length === 0}
          >
            Send invitation
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function EditRolesDialog({
  member,
  roles,
  onOpenChange,
  onSaved,
}: {
  member: MemberSummary | null;
  roles: RoleSummary[];
  onOpenChange: (open: boolean) => void;
  onSaved: () => void;
}) {
  const { permissions } = useAuth();
  const [selected, setSelected] = useState<string[]>([]);
  const [initialised, setInitialised] = useState<string | null>(null);

  if (member && initialised !== member.membership_id) {
    setInitialised(member.membership_id);
    setSelected(member.roles.map((role) => role.id));
  }

  const mutation = useMutation({
    mutationFn: () => api.organization.updateMember(member!.membership_id, selected),
    onSuccess: () => {
      toast.success("Roles updated. The change applies on their next request.");
      onOpenChange(false);
      onSaved();
    },
    onError: (error) =>
      toast.error(error instanceof ApiError ? error.message : "Could not update the roles."),
  });

  return (
    <Dialog open={Boolean(member)} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Roles for {member?.email}</DialogTitle>
          <DialogDescription>
            Permissions are re-resolved on every request, so a change takes effect
            immediately rather than at token expiry.
          </DialogDescription>
        </DialogHeader>

        <RolePicker
          roles={roles}
          selected={selected}
          heldPermissions={permissions}
          onToggle={(roleId) =>
            setSelected((current) =>
              current.includes(roleId)
                ? current.filter((id) => id !== roleId)
                : [...current, roleId],
            )
          }
        />

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            loading={mutation.isPending}
            disabled={selected.length === 0}
            onClick={() => mutation.mutate()}
          >
            Save roles
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
