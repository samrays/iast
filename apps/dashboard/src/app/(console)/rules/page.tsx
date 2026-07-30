"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import { useState } from "react";

import { ErrorState, PageHeader, TableSkeleton } from "@/components/common";
import { Badge, severityVariant } from "@/components/ui/badge";
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

export default function RulesPage() {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const [pending, setPending] = useState<string | null>(null);
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);

  const rules = useQuery({
    queryKey: ["rules"],
    queryFn: () => api.rules.list(),
    enabled: can(Permission.POLICY_READ),
  });

  const toggle = useMutation({
    mutationFn: ({ key, enabled }: { key: string; enabled: boolean }) =>
      api.rules.setEnabled(key, { enabled, reason: reasons[key] ?? "" }),
    onMutate: ({ key }) => {
      setPending(key);
      setError(null);
    },
    onSuccess: () =>
      void queryClient.invalidateQueries({ queryKey: ["rules"] }),
    onError: (caught: unknown) =>
      setError(
        caught instanceof ApiError
          ? caught.message
          : "Could not change the rule.",
      ),
    onSettled: () => setPending(null),
  });

  if (!can(Permission.POLICY_READ)) {
    return (
      <ErrorState
        error={
          new ApiError(403, null, "Your role does not include policy:read.")
        }
      />
    );
  }

  const canWrite = can(Permission.POLICY_WRITE);
  const disabledCount = rules.data?.filter((rule) => !rule.enabled).length ?? 0;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Detection rules"
        description="What the agent looks for. Everything is on until you turn it off."
      />

      {disabledCount > 0 ? (
        <Card>
          <CardContent className="p-4 text-sm">
            {/* Stated plainly rather than buried: switched-off detection is invisible in a
                findings list, which is exactly what makes it worth surfacing here. */}
            <span className="font-medium text-severity-high">
              {disabledCount} rule{disabledCount === 1 ? " is" : "s are"}{" "}
              switched off.
            </span>{" "}
            <span className="text-muted-foreground">
              Vulnerabilities matching {disabledCount === 1 ? "it" : "them"}{" "}
              will not be reported for this organization.
            </span>
          </CardContent>
        </Card>
      ) : null}

      {error ? <p className="text-sm text-severity-critical">{error}</p> : null}

      {rules.isLoading ? (
        <TableSkeleton rows={11} />
      ) : rules.isError ? (
        <ErrorState error={rules.error} onRetry={() => rules.refetch()} />
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Rule</TableHead>
                  <TableHead className="w-28">Severity</TableHead>
                  <TableHead className="w-24">CWE</TableHead>
                  <TableHead>
                    {canWrite ? "Reason if switching off" : "Status"}
                  </TableHead>
                  <TableHead className="w-28" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {rules.data?.map((rule) => (
                  <TableRow
                    key={rule.key}
                    className={rule.enabled ? undefined : "opacity-60"}
                  >
                    <TableCell>
                      <p className="font-medium">{rule.title}</p>
                      <p className="mt-0.5 text-xs text-muted-foreground">
                        {rule.description}
                      </p>
                    </TableCell>
                    <TableCell>
                      <Badge variant={severityVariant(rule.severity)}>
                        {rule.severity}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {rule.cwe_id ? `CWE-${rule.cwe_id}` : "—"}
                    </TableCell>
                    <TableCell>
                      {!rule.enabled ? (
                        <span className="text-xs text-muted-foreground">
                          {rule.disabled_reason || "No reason recorded."}
                        </span>
                      ) : canWrite ? (
                        <Input
                          className="h-8 text-xs"
                          placeholder="Required to switch off"
                          value={reasons[rule.key] ?? ""}
                          onChange={(event) =>
                            setReasons((current) => ({
                              ...current,
                              [rule.key]: event.target.value,
                            }))
                          }
                          aria-label={`Reason for switching off ${rule.title}`}
                        />
                      ) : (
                        <span className="text-xs text-muted-foreground">
                          Active
                        </span>
                      )}
                    </TableCell>
                    <TableCell>
                      {canWrite ? (
                        <Button
                          size="sm"
                          variant={rule.enabled ? "outline" : "default"}
                          disabled={
                            pending === rule.key ||
                            (rule.enabled && !(reasons[rule.key] ?? "").trim())
                          }
                          onClick={() =>
                            toggle.mutate({
                              key: rule.key,
                              enabled: !rule.enabled,
                            })
                          }
                        >
                          {rule.enabled ? "Switch off" : "Switch on"}
                        </Button>
                      ) : (
                        <Badge variant={rule.enabled ? "success" : "disabled"}>
                          {rule.enabled ? "on" : "off"}
                        </Badge>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
        <ShieldCheck className="size-3.5" />
        Every change is recorded in the audit log.
      </p>
    </div>
  );
}
