"use client";

import { useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useEffect, useRef } from "react";
import { toast } from "sonner";

import { API_BASE_URL, tokenStore } from "./api-client";
import { useAuth } from "./auth-provider";

export interface FindingStreamEvent {
  type: "FINDING_CREATED" | "FINDING_UPDATED";
  finding_id: string;
  rule_key: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  confidence: string;
  sink_signature: string;
  application_id: string;
  occurrence_count: number;
  observed_at: string;
}

/**
 * Real-time Server-Sent Events (SSE) listener for finding detections.
 *
 * Connects to `/api/v1/findings/stream` when authenticated, pushes toast alerts
 * on incoming attacks, and invalidates active query caches.
 */
export function useFindingsStream(): void {
  const { status } = useAuth();
  const queryClient = useQueryClient();
  const router = useRouter();
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (status !== "authenticated") {
      if (esRef.current) {
        esRef.current.close();
        esRef.current = null;
      }
      return;
    }

    const token = tokenStore.get();
    if (!token) return;

    const streamUrl = `${API_BASE_URL}/api/v1/findings/stream?token=${encodeURIComponent(token)}`;
    const eventSource = new EventSource(streamUrl);
    esRef.current = eventSource;

    eventSource.addEventListener("finding", (rawEvent) => {
      try {
        const event = JSON.parse(rawEvent.data) as FindingStreamEvent;
        
        // Invalidate queries so tables and charts refresh automatically
        void queryClient.invalidateQueries({ queryKey: ["findings"] });
        void queryClient.invalidateQueries({ queryKey: ["fleet-alerts"] });
        void queryClient.invalidateQueries({ queryKey: ["overview-metrics"] });

        // Show real-time notification
        const isCritical = event.severity === "CRITICAL" || event.severity === "HIGH";
        const title = `Aegis IAST Alert: ${event.rule_key} (${event.severity})`;
        const desc = `Sink: ${event.sink_signature}`;

        if (isCritical) {
          toast.error(title, {
            description: desc,
            action: {
              label: "View Finding",
              onClick: () => router.push(`/findings/${event.finding_id}`),
            },
          });
        } else {
          toast.warning(title, {
            description: desc,
            action: {
              label: "View Finding",
              onClick: () => router.push(`/findings/${event.finding_id}`),
            },
          });
        }
      } catch (err) {
        console.error("Failed to parse finding stream event:", err);
      }
    });

    eventSource.onerror = () => {
      // Reconnection will automatically be attempted by the browser EventSource
    };

    return () => {
      eventSource.close();
      esRef.current = null;
    };
  }, [status, queryClient, router]);
}
