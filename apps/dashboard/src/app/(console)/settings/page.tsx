"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTheme } from "next-themes";
import { Monitor, Moon, ShieldCheck, Sun } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import { CopyButton, DetailList, PageHeader } from "@/components/common";
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
import { Separator, Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/misc";
import { ApiError, api } from "@/lib/api-client";
import { useAuth } from "@/lib/auth-provider";
import { Permission } from "@/lib/permissions";
import type { MfaEnrolResponse } from "@/lib/types";
import { cn } from "@/lib/utils";

export default function SettingsPage() {
  const { principal, can } = useAuth();

  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings"
        description={`Account and organization configuration for ${principal?.organization.name ?? ""}.`}
      />

      <Tabs defaultValue="account">
        <TabsList>
          <TabsTrigger value="account">Account</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
          {can(Permission.ORG_WRITE) ? (
            <TabsTrigger value="organization">Organization</TabsTrigger>
          ) : null}
          <TabsTrigger value="appearance">Appearance</TabsTrigger>
        </TabsList>

        <TabsContent value="account">
          <AccountTab />
        </TabsContent>
        <TabsContent value="security">
          <SecurityTab />
        </TabsContent>
        {can(Permission.ORG_WRITE) ? (
          <TabsContent value="organization">
            <OrganizationTab />
          </TabsContent>
        ) : null}
        <TabsContent value="appearance">
          <AppearanceTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function AccountTab() {
  const { principal } = useAuth();

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Your account</CardTitle>
        <CardDescription>Identity is platform-wide; roles are per organization.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <DetailList
          items={[
            { label: "Name", value: principal?.full_name || "—" },
            { label: "Email", value: principal?.email ?? "—" },
            {
              label: "Organization",
              value: (
                <span className="flex items-center gap-2">
                  {principal?.organization.name}
                  <Badge variant="outline">{principal?.organization.slug}</Badge>
                </span>
              ),
            },
            {
              label: "Roles",
              value: (
                <span className="flex flex-wrap gap-1">
                  {principal?.roles.map((role) => (
                    <Badge key={role.id}>{role.name}</Badge>
                  ))}
                </span>
              ),
            },
          ]}
        />

        <Separator />

        <div>
          <p className="mb-2 text-2xs font-semibold uppercase tracking-wide text-muted-foreground">
            Effective permissions ({principal?.permissions.length ?? 0})
          </p>
          <div className="flex flex-wrap gap-1">
            {principal?.permissions.map((permission) => (
              <Badge key={permission} variant="secondary" className="font-mono normal-case">
                {permission}
              </Badge>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function SecurityTab() {
  const { principal, reload, logout } = useAuth();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [passwordErrors, setPasswordErrors] = useState<string[]>([]);
  const [enrolment, setEnrolment] = useState<MfaEnrolResponse | null>(null);
  const [mfaDialogOpen, setMfaDialogOpen] = useState(false);
  const [mfaPassword, setMfaPassword] = useState("");
  const [confirmCode, setConfirmCode] = useState("");

  const changePassword = useMutation({
    mutationFn: () => api.auth.changePassword(currentPassword, newPassword),
    onSuccess: (result) => {
      toast.success(
        `Password changed. ${result.sessions_revoked} other session(s) were signed out.`,
      );
      setCurrentPassword("");
      setNewPassword("");
      setPasswordErrors([]);
    },
    onError: (error) => {
      if (error instanceof ApiError) {
        // The API returns every policy failure at once rather than one at a time.
        const failures = (error.problem?.errors ?? []).map((item) => item.message);
        setPasswordErrors(failures.length > 0 ? failures : [error.message]);
        return;
      }
      setPasswordErrors(["Could not change the password."]);
    },
  });

  const startEnrolment = useMutation({
    mutationFn: () => api.auth.enrolMfa(mfaPassword),
    onSuccess: (result) => {
      setEnrolment(result);
      setMfaPassword("");
    },
    onError: (error) =>
      toast.error(error instanceof ApiError ? error.message : "Could not start enrolment."),
  });

  const confirmEnrolment = useMutation({
    mutationFn: () => api.auth.confirmMfa(confirmCode),
    onSuccess: async () => {
      toast.success("Multi-factor authentication is on.");
      setEnrolment(null);
      setConfirmCode("");
      setMfaDialogOpen(false);
      await reload();
    },
    onError: (error) =>
      toast.error(error instanceof ApiError ? error.message : "That code was not accepted."),
  });

  const disableMfa = useMutation({
    mutationFn: () => api.auth.disableMfa(mfaPassword),
    onSuccess: async () => {
      toast.success("Multi-factor authentication disabled.");
      setMfaPassword("");
      setMfaDialogOpen(false);
      await reload();
    },
    onError: (error) =>
      toast.error(error instanceof ApiError ? error.message : "Could not disable MFA."),
  });

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Multi-factor authentication</CardTitle>
          <CardDescription>
            A second factor is the single most effective control against a stolen password.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span
              className={cn(
                "flex size-9 items-center justify-center rounded-full",
                principal?.mfa_enabled
                  ? "bg-status-online-surface text-status-online"
                  : "bg-severity-medium-surface text-severity-medium",
              )}
            >
              <ShieldCheck className="size-5" />
            </span>
            <div>
              <p className="text-sm font-medium">
                {principal?.mfa_enabled ? "Enabled" : "Not enabled"}
              </p>
              <p className="text-xs text-muted-foreground">
                {principal?.mfa_enabled
                  ? "You are asked for a code after your password."
                  : "Anyone with your password can sign in as you."}
              </p>
            </div>
          </div>
          <Button
            variant={principal?.mfa_enabled ? "outline" : "default"}
            onClick={() => setMfaDialogOpen(true)}
          >
            {principal?.mfa_enabled ? "Disable" : "Enable"}
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Change password</CardTitle>
          <CardDescription>
            Changing it signs out every other session — which is exactly what you want if
            you suspect one is not yours.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="max-w-sm space-y-4"
            onSubmit={(event) => {
              event.preventDefault();
              changePassword.mutate();
            }}
          >
            <div className="space-y-2">
              <Label htmlFor="current-password">Current password</Label>
              <Input
                id="current-password"
                type="password"
                autoComplete="current-password"
                required
                value={currentPassword}
                onChange={(event) => setCurrentPassword(event.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="new-password">New password</Label>
              <Input
                id="new-password"
                type="password"
                autoComplete="new-password"
                required
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
                aria-invalid={passwordErrors.length > 0}
              />
              {passwordErrors.length > 0 ? (
                <ul className="space-y-0.5 text-xs text-destructive">
                  {passwordErrors.map((message) => (
                    <li key={message}>{message}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-muted-foreground">
                  At least 12 characters. Length beats symbols.
                </p>
              )}
            </div>
            <Button type="submit" loading={changePassword.isPending}>
              Change password
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Sessions</CardTitle>
          <CardDescription>
            Your access token lives in memory only and expires every 15 minutes. The refresh
            cookie is HttpOnly and rotates on every use.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button variant="outline" onClick={() => void logout(true)}>
            Sign out everywhere
          </Button>
        </CardContent>
      </Card>

      <Dialog
        open={mfaDialogOpen}
        onOpenChange={(open) => {
          setMfaDialogOpen(open);
          if (!open) {
            setEnrolment(null);
            setMfaPassword("");
            setConfirmCode("");
          }
        }}
      >
        <DialogContent>
          {principal?.mfa_enabled ? (
            <>
              <DialogHeader>
                <DialogTitle>Disable multi-factor authentication</DialogTitle>
                <DialogDescription>
                  Confirm with your password. Every stored factor and recovery code is
                  removed.
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-2">
                <Label htmlFor="mfa-disable-password">Password</Label>
                <Input
                  id="mfa-disable-password"
                  type="password"
                  autoComplete="current-password"
                  value={mfaPassword}
                  onChange={(event) => setMfaPassword(event.target.value)}
                />
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setMfaDialogOpen(false)}>
                  Cancel
                </Button>
                <Button
                  variant="destructive"
                  loading={disableMfa.isPending}
                  disabled={!mfaPassword}
                  onClick={() => disableMfa.mutate()}
                >
                  Disable
                </Button>
              </DialogFooter>
            </>
          ) : enrolment ? (
            <>
              <DialogHeader>
                <DialogTitle>Finish enrolment</DialogTitle>
                <DialogDescription>
                  Add the secret to your authenticator, then enter a code to prove it works.
                  Confirming is what stops a mis-scanned code locking you out.
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-3">
                <div>
                  <p className="mb-1 text-2xs font-semibold uppercase tracking-wide text-muted-foreground">
                    Secret
                  </p>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 overflow-x-auto rounded-md border border-border bg-muted px-3 py-2 font-mono text-xs">
                      {enrolment.secret}
                    </code>
                    <CopyButton value={enrolment.secret} label="Copy" />
                  </div>
                </div>

                <div>
                  <p className="mb-1 text-2xs font-semibold uppercase tracking-wide text-muted-foreground">
                    Recovery codes — stored nowhere else
                  </p>
                  <div className="grid grid-cols-2 gap-1 rounded-md border border-border bg-muted p-3 font-mono text-xs">
                    {enrolment.recovery_codes.map((code) => (
                      <span key={code}>{code}</span>
                    ))}
                  </div>
                  <div className="mt-2">
                    <CopyButton
                      value={enrolment.recovery_codes.join("\n")}
                      label="Copy recovery codes"
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="mfa-confirm">Code from your authenticator</Label>
                  <Input
                    id="mfa-confirm"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    value={confirmCode}
                    onChange={(event) => setConfirmCode(event.target.value)}
                    placeholder="123456"
                    className="text-center font-mono tracking-[0.3em]"
                  />
                </div>
              </div>

              <DialogFooter>
                <Button variant="outline" onClick={() => setMfaDialogOpen(false)}>
                  Cancel
                </Button>
                <Button
                  loading={confirmEnrolment.isPending}
                  disabled={confirmCode.length < 6}
                  onClick={() => confirmEnrolment.mutate()}
                >
                  Confirm and enable
                </Button>
              </DialogFooter>
            </>
          ) : (
            <>
              <DialogHeader>
                <DialogTitle>Enable multi-factor authentication</DialogTitle>
                <DialogDescription>
                  Confirm your password first — an unattended session must not be enough to
                  change your second factor.
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-2">
                <Label htmlFor="mfa-password">Password</Label>
                <Input
                  id="mfa-password"
                  type="password"
                  autoComplete="current-password"
                  value={mfaPassword}
                  onChange={(event) => setMfaPassword(event.target.value)}
                />
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setMfaDialogOpen(false)}>
                  Cancel
                </Button>
                <Button
                  loading={startEnrolment.isPending}
                  disabled={!mfaPassword}
                  onClick={() => startEnrolment.mutate()}
                >
                  Continue
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

function OrganizationTab() {
  const queryClient = useQueryClient();
  const organization = useQuery({
    queryKey: ["organization"],
    queryFn: () => api.organization.current(),
  });
  const [name, setName] = useState("");

  useEffect(() => {
    if (organization.data) setName(organization.data.name);
  }, [organization.data]);

  const update = useMutation({
    mutationFn: () => api.organization.update({ name: name.trim() }),
    onSuccess: () => {
      toast.success("Organization updated.");
      void queryClient.invalidateQueries({ queryKey: ["organization"] });
    },
    onError: (error) =>
      toast.error(error instanceof ApiError ? error.message : "Could not update the organization."),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Organization</CardTitle>
        <CardDescription>
          The slug is permanent — it appears in agent configuration and sign-in URLs.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="max-w-sm space-y-4"
          onSubmit={(event) => {
            event.preventDefault();
            update.mutate();
          }}
        >
          <div className="space-y-2">
            <Label htmlFor="org-name">Display name</Label>
            <Input
              id="org-name"
              required
              value={name}
              onChange={(event) => setName(event.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="org-slug">Slug</Label>
            <Input
              id="org-slug"
              readOnly
              disabled
              value={organization.data?.slug ?? ""}
              className="font-mono text-xs"
            />
          </div>
          <Button type="submit" loading={update.isPending}>
            Save changes
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

function AppearanceTab() {
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  const options = [
    { value: "light", label: "Light", icon: Sun, hint: "Default. Best under office lighting." },
    { value: "dark", label: "Dark", icon: Moon, hint: "For dim rooms and wall displays." },
    { value: "system", label: "System", icon: Monitor, hint: "Follow your operating system." },
  ];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Theme</CardTitle>
        <CardDescription>Stored in this browser, not on your account.</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid gap-3 sm:grid-cols-3">
          {options.map((option) => {
            const active = mounted && theme === option.value;
            return (
              <button
                key={option.value}
                type="button"
                onClick={() => setTheme(option.value)}
                aria-pressed={active}
                className={cn(
                  "flex flex-col items-start gap-1.5 rounded-lg border p-4 text-left transition-colors",
                  active ? "border-primary bg-accent/50" : "border-border hover:bg-accent/30",
                )}
              >
                <option.icon className="size-4 text-muted-foreground" aria-hidden />
                <span className="text-sm font-medium">{option.label}</span>
                <span className="text-xs text-muted-foreground">{option.hint}</span>
              </button>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
