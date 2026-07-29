"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";

import { ErrorState, PageHeader } from "@/components/common";
import { Badge, findingStatusVariant, severityVariant } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError, api } from "@/lib/api-client";
import { useAuth } from "@/lib/auth-provider";
import { Permission } from "@/lib/permissions";
import type { FindingStatus, Occurrence } from "@/lib/types";
import { absoluteTime, relativeTime } from "@/lib/utils";

/** Transitions a person can pick, and the permission each needs. */
const TRANSITIONS: { status: FindingStatus; label: string; suppresses: boolean }[] = [
  { status: "CONFIRMED", label: "Confirm", suppresses: false },
  { status: "REMEDIATED", label: "Mark remediated", suppresses: false },
  { status: "FALSE_POSITIVE", label: "False positive", suppresses: true },
  { status: "ACCEPTED_RISK", label: "Accept risk", suppresses: true },
  { status: "OPEN", label: "Reopen", suppresses: false },
];

/**
 * Render the sink argument with the attacker-controlled characters marked.
 *
 * This is the single most useful thing on the page: it turns "SQL injection" into "these ten
 * characters, which came from the `name` parameter, are why". Ranges are clipped and sorted
 * defensively — they describe a string an attacker influenced, so they are not trusted to be
 * well-formed.
 */
function TaintedArgument({ occurrence }: { occurrence: Occurrence }) {
  const text = occurrence.sink_argument;
  const ranges = [...occurrence.tainted_ranges]
    .filter((range) => range.length > 0 && range.start >= 0 && range.start < text.length)
    .sort((a, b) => a.start - b.start);

  const parts: React.ReactNode[] = [];
  let cursor = 0;
  ranges.forEach((range, index) => {
    const end = Math.min(range.start + range.length, text.length);
    if (range.start > cursor) parts.push(text.slice(cursor, range.start));
    parts.push(
      <mark
        key={`${range.start}-${index}`}
        className="rounded-sm bg-severity-critical-surface px-0.5 font-semibold text-severity-critical"
        title={`from ${range.source.replace("SOURCE_KIND_", "").toLowerCase()} “${range.source_name}”`}
      >
        {text.slice(range.start, end)}
      </mark>,
    );
    cursor = Math.max(cursor, end);
  });
  if (cursor < text.length) parts.push(text.slice(cursor));

  return (
    <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-md bg-muted p-3 font-mono text-xs">
      {parts}
    </pre>
  );
}

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const [note, setNote] = useState("");
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | null>(null);

  const finding = useQuery({
    queryKey: ["findings", id],
    queryFn: () => api.findings.get(id),
    enabled: can(Permission.FINDING_READ),
  });

  const triage = useMutation({
    mutationFn: (status: FindingStatus) =>
      api.findings.triage(id, {
        status,
        note,
        ...(status === "ACCEPTED_RISK" ? { accepted_for_days: 90 } : {}),
      }),
    onSuccess: () => {
      setNote("");
      setError(null);
      void queryClient.invalidateQueries({ queryKey: ["findings"] });
    },
    onError: (caught: unknown) =>
      setError(caught instanceof ApiError ? caught.message : "Could not update the finding."),
  });

  const addComment = useMutation({
    mutationFn: () => api.findings.comment(id, comment),
    onSuccess: () => {
      setComment("");
      void queryClient.invalidateQueries({ queryKey: ["findings", id] });
    },
  });

  if (!can(Permission.FINDING_READ)) {
    return (
      <ErrorState error={new ApiError(403, null, "Your role does not include finding:read.")} />
    );
  }
  if (finding.isError) return <ErrorState error={finding.error} />;
  if (!finding.data) return <p className="text-sm text-muted-foreground">Loading…</p>;

  const item = finding.data;
  // The most recent sample the worker kept. Absent only for a finding whose evidence has
  // aged out of retention, which the page has to survive rather than crash on.
  const latest = item.occurrences[0];
  const canTriage = can(Permission.FINDING_TRIAGE);
  const canSuppress = can(Permission.FINDING_SUPPRESS);

  return (
    <div className="space-y-6">
      <Link
        href="/findings"
        className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="size-4" /> All findings
      </Link>

      <PageHeader title={item.title} description={item.sink_signature} />

      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={severityVariant(item.severity)}>{item.severity}</Badge>
        <Badge variant={findingStatusVariant(item.status)}>{item.status.replace("_", " ")}</Badge>
        <Badge variant="outline">{item.confidence}</Badge>
        {item.cwe_id ? <Badge variant="outline">CWE-{item.cwe_id}</Badge> : null}
        {item.regressed ? <Badge variant="critical">regressed</Badge> : null}
        <span className="text-sm text-muted-foreground">
          seen {item.occurrence_count}× · last {relativeTime(item.last_seen_at)}
        </span>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          {latest ? (
            <Card>
              <CardHeader>
                <CardTitle>Evidence</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <p className="mb-1.5 text-xs font-medium text-muted-foreground">
                    {latest.request_method} {latest.request_path} ·{" "}
                    {latest.environment}
                  </p>
                  <TaintedArgument occurrence={latest} />
                  <p className="mt-1.5 text-xs text-muted-foreground">
                    Highlighted characters reached the sink from the request.
                  </p>
                </div>

                <div>
                  <p className="mb-1.5 text-xs font-medium text-muted-foreground">Call path</p>
                  <ol className="space-y-0.5 font-mono text-xs">
                    {latest.stack_frames.map((frame, index) => (
                      <li
                        key={index}
                        className={
                          frame.application_code ? "text-foreground" : "text-muted-foreground/60"
                        }
                      >
                        {frame.declaring_class}#{frame.method_name}
                        {frame.line_number > 0 ? `:${frame.line_number}` : ""}
                      </li>
                    ))}
                  </ol>
                  <p className="mt-1.5 text-xs text-muted-foreground">
                    Your code is shown in full contrast; framework frames are dimmed.
                  </p>
                </div>
              </CardContent>
            </Card>
          ) : null}

          <Card>
            <CardHeader>
              <CardTitle>Triage history</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {item.comments.length === 0 ? (
                <p className="text-sm text-muted-foreground">Nothing recorded yet.</p>
              ) : (
                item.comments.map((entry) => (
                  <div key={entry.id} className="border-l-2 border-border pl-3">
                    <p className="text-sm">{entry.body}</p>
                    <p className="mt-0.5 text-xs text-muted-foreground">
                      {entry.author_label || "system"} · {absoluteTime(entry.created_at)}
                      {entry.status_to ? ` · → ${entry.status_to.replace("_", " ")}` : ""}
                    </p>
                  </div>
                ))
              )}
              {canTriage ? (
                <div className="flex gap-2 pt-2">
                  <Input
                    value={comment}
                    onChange={(event) => setComment(event.target.value)}
                    placeholder="Add a note…"
                    aria-label="Add a comment"
                  />
                  <Button
                    variant="outline"
                    disabled={!comment.trim() || addComment.isPending}
                    onClick={() => addComment.mutate()}
                  >
                    Comment
                  </Button>
                </div>
              ) : null}
            </CardContent>
          </Card>
        </div>

        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Why this score</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="mb-3 font-mono text-2xl tabular-nums">
                {item.risk_score.toFixed(1)}
                <span className="text-sm text-muted-foreground"> / 10</span>
              </p>
              <ul className="space-y-1.5">
                {item.risk_factors.map((factor) => (
                  <li key={factor.name} className="text-xs">
                    <span className="font-mono tabular-nums text-muted-foreground">
                      {factor.delta >= 0 ? "+" : ""}
                      {factor.delta.toFixed(2)}
                    </span>{" "}
                    <span className="font-medium">{factor.name}</span>
                    <span className="text-muted-foreground"> — {factor.reason}</span>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>

          {canTriage || canSuppress ? (
            <Card>
              <CardHeader>
                <CardTitle>Triage</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div>
                  <Label htmlFor="triage-note">Reason</Label>
                  <Input
                    id="triage-note"
                    value={note}
                    onChange={(event) => setNote(event.target.value)}
                    placeholder="Required when suppressing"
                  />
                </div>
                <div className="flex flex-wrap gap-2">
                  {TRANSITIONS.filter((t) => t.status !== item.status)
                    .filter((t) => (t.suppresses ? canSuppress : canTriage))
                    .map((transition) => (
                      <Button
                        key={transition.status}
                        size="sm"
                        variant={transition.suppresses ? "outline" : "default"}
                        disabled={triage.isPending}
                        onClick={() => triage.mutate(transition.status)}
                      >
                        {transition.label}
                      </Button>
                    ))}
                </div>
                {error ? <p className="text-xs text-severity-critical">{error}</p> : null}
                {item.accepted_until ? (
                  <p className="text-xs text-muted-foreground">
                    Acceptance expires {absoluteTime(item.accepted_until)}, after which this
                    returns to the open queue.
                  </p>
                ) : null}
              </CardContent>
            </Card>
          ) : null}
        </div>
      </div>
    </div>
  );
}
