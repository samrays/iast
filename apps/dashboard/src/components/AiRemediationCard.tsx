"use client";

import { useMutation } from "@tanstack/react-query";
import { Sparkles, CheckCircle2, XCircle, Bot } from "lucide-react";
import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ApiError, api } from "@/lib/api-client";
import type { AiAnalysis } from "@/lib/types";

interface AiRemediationCardProps {
  findingId: string;
  canTriage: boolean;
}

export function AiRemediationCard({ findingId, canTriage }: AiRemediationCardProps) {
  const [analysis, setAnalysis] = useState<AiAnalysis | null>(null);
  const [reviewNote, setReviewNote] = useState("");
  const [error, setError] = useState<string | null>(null);

  const analyze = useMutation({
    mutationFn: (kind: "ROOT_CAUSE" | "REMEDIATION" | "TRIAGE_ASSESSMENT") =>
      api.ai.analyze(findingId, kind),
    onSuccess: (data) => {
      setAnalysis(data);
      setError(null);
    },
    onError: (caught: unknown) =>
      setError(caught instanceof ApiError ? caught.message : "Failed to run AI analysis."),
  });

  const review = useMutation({
    mutationFn: (accept: boolean) =>
      api.ai.review(analysis!.id, accept, reviewNote),
    onSuccess: (data) => {
      setAnalysis(data);
      setReviewNote("");
      setError(null);
    },
    onError: (caught: unknown) =>
      setError(caught instanceof ApiError ? caught.message : "Failed to record review."),
  });

  return (
    <Card className="border-primary/20 bg-muted/20 shadow-sm">
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="flex items-center gap-2 text-sm font-semibold">
          <Sparkles className="h-4 w-4 text-primary" />
          AI Root Cause & Remediation (Human-in-the-Loop)
        </CardTitle>
        {analysis ? (
          <Badge
            variant={
              analysis.status === "ACCEPTED"
                ? "default"
                : analysis.status === "REJECTED"
                ? "destructive"
                : "secondary"
            }
          >
            {analysis.status}
          </Badge>
        ) : null}
      </CardHeader>
      <CardContent className="space-y-4 text-xs">
        {!analysis ? (
          <div className="space-y-3">
            <p className="text-muted-foreground">
              Synthesize attacker-fenced evidence into an explainable root-cause narrative and
              actionable patch.
            </p>
            <div className="flex flex-wrap gap-2">
              <Button
                size="sm"
                variant="default"
                disabled={analyze.isPending}
                onClick={() => analyze.mutate("ROOT_CAUSE")}
              >
                <Bot className="mr-1.5 h-3.5 w-3.5" /> Explain Root Cause
              </Button>
              <Button
                size="sm"
                variant="outline"
                disabled={analyze.isPending}
                onClick={() => analyze.mutate("REMEDIATION")}
              >
                Generate Remediation
              </Button>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div>
              <p className="font-semibold text-foreground">{analysis.summary}</p>
              <pre className="mt-2 overflow-x-auto whitespace-pre-wrap rounded-md bg-muted p-3 font-mono text-[11px] leading-relaxed">
                {analysis.content}
              </pre>
            </div>

            {analysis.status === "DRAFT" && canTriage ? (
              <div className="space-y-2 pt-2 border-t">
                <Input
                  value={reviewNote}
                  onChange={(e) => setReviewNote(e.target.value)}
                  placeholder="Review note (required when rejecting)"
                />
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    variant="default"
                    disabled={review.isPending}
                    onClick={() => review.mutate(true)}
                  >
                    <CheckCircle2 className="mr-1 h-3.5 w-3.5" /> Accept Patch
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={review.isPending || !reviewNote.trim()}
                    onClick={() => review.mutate(false)}
                  >
                    <XCircle className="mr-1 h-3.5 w-3.5" /> Reject Fix
                  </Button>
                </div>
              </div>
            ) : null}
          </div>
        )}
        {error ? <p className="text-xs text-severity-critical">{error}</p> : null}
      </CardContent>
    </Card>
  );
}
