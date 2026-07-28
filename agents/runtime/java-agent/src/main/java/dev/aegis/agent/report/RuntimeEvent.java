package dev.aegis.agent.report;

import dev.aegis.agent.detect.Finding;
import dev.aegis.agent.runtime.RequestContext;
import dev.aegis.agent.taint.TaintRange;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * One telemetry event, ready to serialize.
 *
 * <p>Hand-rolled JSON rather than a serialization library. An agent injected into someone
 * else's process should add as close to zero classes to their heap as possible, and every
 * dependency is one more version conflict waiting to surface in production. The shapes match
 * {@code packages/proto/agent/v1/events.proto} field for field.
 */
public final class RuntimeEvent {

    private final String eventId;
    private final String type;
    private final long occurredAtMs;
    private final long monotonicNanos;
    private final String traceId;
    private final String json;

    private RuntimeEvent(
            String eventId, String type, String traceId, String payloadJson) {
        this.eventId = eventId;
        this.type = type;
        this.occurredAtMs = System.currentTimeMillis();
        this.monotonicNanos = System.nanoTime();
        this.traceId = traceId == null ? "" : traceId;
        this.json = payloadJson;
    }

    public String eventId() {
        return eventId;
    }

    public String type() {
        return type;
    }

    static RuntimeEvent taintHit(String eventId, Finding finding, RequestContext context) {
        StringBuilder payload = new StringBuilder(512);
        payload.append("\"taint_hit\":{");
        field(payload, "rule_key", finding.rule().key());
        payload.append(',');
        field(payload, "severity", finding.effectiveSeverity().wireName());
        payload.append(',');
        field(payload, "confidence", "CONFIDENCE_" + finding.confidence().name());
        payload.append(',');
        field(payload, "sink_signature", finding.sinkSignature());
        payload.append(',');
        field(payload, "sink_argument", finding.sinkArgument());
        payload.append(',');
        field(payload, "stack_fingerprint", finding.stackFingerprint());
        payload.append(",\"imprecise\":").append(finding.isImprecise());

        payload.append(",\"ranges\":[");
        List<TaintRange> ranges = finding.ranges();
        for (int i = 0; i < ranges.size(); i++) {
            TaintRange range = ranges.get(i);
            if (i > 0) {
                payload.append(',');
            }
            payload.append("{\"start\":").append(range.start());
            payload.append(",\"length\":").append(range.length());
            payload.append(",\"source\":\"").append(range.source().wireName()).append('"');
            payload.append(",\"source_name\":");
            quote(payload, range.sourceName());
            payload.append('}');
        }
        payload.append(']');

        payload.append(",\"stack\":[");
        List<Finding.StackFrame> stack = finding.stack();
        for (int i = 0; i < stack.size(); i++) {
            Finding.StackFrame frame = stack.get(i);
            if (i > 0) {
                payload.append(',');
            }
            payload.append("{\"declaring_class\":");
            quote(payload, frame.declaringClass());
            payload.append(",\"method_name\":");
            quote(payload, frame.methodName());
            payload.append(",\"line_number\":").append(frame.lineNumber());
            payload.append(",\"application_code\":").append(frame.applicationCode());
            payload.append('}');
        }
        payload.append(']');

        payload.append(",\"sanitizers_applied\":");
        stringArray(payload, finding.sanitizersApplied());

        if (context != null) {
            payload.append(",\"request\":{");
            field(payload, "method", context.method());
            payload.append(',');
            field(payload, "path", context.path());
            payload.append(',');
            field(payload, "route_template", context.routeTemplate());
            payload.append(',');
            field(payload, "remote_addr", context.remoteAddr());
            payload.append(",\"parameters\":");
            stringMap(payload, context.parameters());
            payload.append(",\"headers\":");
            stringMap(payload, context.headers());
            payload.append(',');
            field(payload, "body_excerpt", context.bodyExcerpt());
            payload.append('}');
        }

        payload.append('}');
        return new RuntimeEvent(
                eventId,
                "EVENT_TYPE_TAINT_HIT",
                context == null ? "" : context.traceId(),
                payload.toString());
    }

    static RuntimeEvent route(
            String eventId, String method, String pathTemplate, boolean authenticated) {
        StringBuilder payload = new StringBuilder(96);
        payload.append("\"route\":{");
        field(payload, "method", method);
        payload.append(',');
        field(payload, "path_template", pathTemplate);
        payload.append(",\"authenticated\":").append(authenticated);
        payload.append('}');
        return new RuntimeEvent(eventId, "EVENT_TYPE_ROUTE", "", payload.toString());
    }

    static RuntimeEvent coverageGap(String eventId, String reason, String component) {
        StringBuilder payload = new StringBuilder(96);
        payload.append("\"coverage_gap\":{");
        field(payload, "reason", reason);
        payload.append(',');
        field(payload, "component", component);
        payload.append('}');
        return new RuntimeEvent(eventId, "EVENT_TYPE_COVERAGE_GAP", "", payload.toString());
    }

    /** One NDJSON line, as sent to the ingest gateway. */
    public String toJson() {
        StringBuilder builder = new StringBuilder(json.length() + 160);
        builder.append('{');
        field(builder, "event_id", eventId);
        builder.append(',');
        field(builder, "type", type);
        builder.append(",\"occurred_at_ms\":").append(occurredAtMs);
        builder.append(",\"monotonic_nanos\":").append(monotonicNanos);
        builder.append(',');
        field(builder, "trace_id", traceId);
        builder.append(',').append(json);
        builder.append('}');
        return builder.toString();
    }

    // --- minimal JSON writing -------------------------------------------------------

    private static void field(StringBuilder builder, String name, String value) {
        builder.append('"').append(name).append("\":");
        quote(builder, value);
    }

    private static void stringArray(StringBuilder builder, List<String> values) {
        builder.append('[');
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                builder.append(',');
            }
            quote(builder, values.get(i));
        }
        builder.append(']');
    }

    private static void stringMap(StringBuilder builder, Map<String, String> values) {
        builder.append('{');
        boolean first = true;
        List<Map.Entry<String, String>> entries = new ArrayList<>(values.entrySet());
        for (Map.Entry<String, String> entry : entries) {
            if (!first) {
                builder.append(',');
            }
            first = false;
            quote(builder, entry.getKey());
            builder.append(':');
            quote(builder, entry.getValue());
        }
        builder.append('}');
    }

    /**
     * Escape per RFC 8259.
     *
     * <p>This runs over attacker-controlled bytes on every finding, so it escapes control
     * characters explicitly rather than trusting them to pass through — a raw newline here
     * would split one NDJSON record into two and corrupt the ingest stream.
     */
    static void quote(StringBuilder builder, String value) {
        if (value == null) {
            builder.append("\"\"");
            return;
        }
        builder.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> builder.append("\\\"");
                case '\\' -> builder.append("\\\\");
                case '\n' -> builder.append("\\n");
                case '\r' -> builder.append("\\r");
                case '\t' -> builder.append("\\t");
                case '\b' -> builder.append("\\b");
                case '\f' -> builder.append("\\f");
                default -> {
                    if (c < 0x20) {
                        builder.append(String.format("\\u%04x", (int) c));
                    } else {
                        builder.append(c);
                    }
                }
            }
        }
        builder.append('"');
    }
}
