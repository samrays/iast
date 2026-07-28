package dev.aegis.agent;

import dev.aegis.agent.redact.Redactor;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Agent configuration.
 *
 * <p>Precedence is local file &lt; environment &lt; remote, with one asymmetry that matters:
 * remote configuration may only ever <em>reduce</em> data capture, never widen it beyond the
 * locally configured maximum. The customer keeps the veto over what leaves their process
 * (docs/05 §9) — otherwise a control-plane compromise becomes a data-exfiltration channel.
 */
public final class AgentConfig {

    private final String endpoint;
    private final String apiKey;
    private final String applicationName;
    private final String environment;
    private final double cpuBudgetPct;
    private final int maxMemoryMb;
    private final Redactor.CaptureMode captureMode;
    private final int maxValueLength;
    private final Set<String> redactKeys;
    private final Set<String> applicationPackages;
    private final int bufferCapacity;
    private final int heartbeatSeconds;
    private final boolean blockingEnabled;

    private AgentConfig(Builder builder) {
        this.endpoint = builder.endpoint;
        this.apiKey = builder.apiKey;
        this.applicationName = builder.applicationName;
        this.environment = builder.environment;
        this.cpuBudgetPct = builder.cpuBudgetPct;
        this.maxMemoryMb = builder.maxMemoryMb;
        this.captureMode = builder.captureMode;
        this.maxValueLength = builder.maxValueLength;
        this.redactKeys = Set.copyOf(builder.redactKeys);
        this.applicationPackages = Set.copyOf(builder.applicationPackages);
        this.bufferCapacity = builder.bufferCapacity;
        this.heartbeatSeconds = builder.heartbeatSeconds;
        this.blockingEnabled = builder.blockingEnabled;
    }

    /** Parse the {@code -javaagent:aegis.jar=key=value,key=value} argument and the environment. */
    public static AgentConfig fromAgentArgs(String agentArgs) {
        Builder builder = new Builder();

        // Environment first, so an explicit agent argument can override it.
        applyIfPresent(builder, "endpoint", System.getenv("AEGIS_ENDPOINT"));
        applyIfPresent(builder, "api_key", System.getenv("AEGIS_API_KEY"));
        applyIfPresent(builder, "application", System.getenv("AEGIS_APPLICATION_NAME"));
        applyIfPresent(builder, "environment", System.getenv("AEGIS_ENVIRONMENT"));
        applyIfPresent(builder, "cpu_budget_pct", System.getenv("AEGIS_CPU_BUDGET_PCT"));
        applyIfPresent(builder, "capture", System.getenv("AEGIS_CAPTURE_REQUEST_BODY"));
        applyIfPresent(builder, "redact_keys", System.getenv("AEGIS_REDACT_KEYS"));
        applyIfPresent(builder, "packages", System.getenv("AEGIS_APPLICATION_PACKAGES"));

        if (agentArgs != null && !agentArgs.isBlank()) {
            for (String pair : agentArgs.split(",")) {
                int equals = pair.indexOf('=');
                if (equals > 0) {
                    applyIfPresent(
                            builder,
                            pair.substring(0, equals).trim().toLowerCase(Locale.ROOT),
                            pair.substring(equals + 1).trim());
                }
            }
        }
        return builder.build();
    }

    private static void applyIfPresent(Builder builder, String key, String value) {
        if (value == null || value.isBlank()) {
            return;
        }
        switch (key) {
            case "endpoint" -> builder.endpoint = value;
            case "api_key", "apikey" -> builder.apiKey = value;
            case "application", "application_name" -> builder.applicationName = value;
            case "environment", "env" -> builder.environment = value.toUpperCase(Locale.ROOT);
            case "cpu_budget_pct" -> builder.cpuBudgetPct = parseDouble(value, 5.0);
            case "max_memory_mb" -> builder.maxMemoryMb = (int) parseDouble(value, 150);
            case "capture", "capture_request_body" -> builder.captureMode = parseCapture(value);
            case "max_value_length" -> builder.maxValueLength = (int) parseDouble(value, 512);
            case "redact_keys" -> builder.redactKeys.addAll(splitList(value));
            case "packages", "application_packages" ->
                    builder.applicationPackages.addAll(splitList(value));
            case "buffer_capacity" -> builder.bufferCapacity = (int) parseDouble(value, 4096);
            case "heartbeat_seconds" -> builder.heartbeatSeconds = (int) parseDouble(value, 30);
            case "blocking" -> builder.blockingEnabled = Boolean.parseBoolean(value);
            default -> {
                // Unknown keys are ignored rather than fatal: a newer control plane must be
                // able to hand an older agent a setting it has never heard of.
            }
        }
    }

    private static Set<String> splitList(String value) {
        return Arrays.stream(value.split("[,;]"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private static double parseDouble(String value, double fallback) {
        try {
            return Double.parseDouble(value);
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static Redactor.CaptureMode parseCapture(String value) {
        try {
            return Redactor.CaptureMode.valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            // An unrecognised capture mode falls back to the *safest* option, never the most
            // permissive one.
            return Redactor.CaptureMode.NONE;
        }
    }

    public String endpoint() {
        return endpoint;
    }

    public String apiKey() {
        return apiKey;
    }

    public String applicationName() {
        return applicationName;
    }

    public String environment() {
        return environment;
    }

    public double cpuBudgetPct() {
        return cpuBudgetPct;
    }

    public int maxMemoryMb() {
        return maxMemoryMb;
    }

    public Redactor.CaptureMode captureMode() {
        return captureMode;
    }

    public int maxValueLength() {
        return maxValueLength;
    }

    public Set<String> redactKeys() {
        return redactKeys;
    }

    public Set<String> applicationPackages() {
        return applicationPackages;
    }

    public int bufferCapacity() {
        return bufferCapacity;
    }

    public int heartbeatSeconds() {
        return heartbeatSeconds;
    }

    public boolean blockingEnabled() {
        return blockingEnabled;
    }

    public Redactor newRedactor() {
        return new Redactor(redactKeys, captureMode, maxValueLength, false);
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Mutable builder; only used during bootstrap, before any application thread runs. */
    public static final class Builder {
        private String endpoint = "http://localhost:8081";
        private String apiKey = "";
        private String applicationName = "unknown-application";
        private String environment = "DEVELOPMENT";
        private double cpuBudgetPct = 5.0;
        private int maxMemoryMb = 150;
        private Redactor.CaptureMode captureMode = Redactor.CaptureMode.TRUNCATED;
        private int maxValueLength = 512;
        private final Set<String> redactKeys = new LinkedHashSet<>();
        private final Set<String> applicationPackages = new LinkedHashSet<>();
        private int bufferCapacity = 4096;
        private int heartbeatSeconds = 30;
        private boolean blockingEnabled = false;

        public Builder endpoint(String value) {
            this.endpoint = value;
            return this;
        }

        public Builder apiKey(String value) {
            this.apiKey = value;
            return this;
        }

        public Builder applicationName(String value) {
            this.applicationName = value;
            return this;
        }

        public Builder environment(String value) {
            this.environment = value;
            return this;
        }

        public Builder cpuBudgetPct(double value) {
            this.cpuBudgetPct = value;
            return this;
        }

        public Builder captureMode(Redactor.CaptureMode value) {
            this.captureMode = value;
            return this;
        }

        public Builder applicationPackages(Set<String> value) {
            this.applicationPackages.addAll(value);
            return this;
        }

        public Builder bufferCapacity(int value) {
            this.bufferCapacity = value;
            return this;
        }

        public AgentConfig build() {
            return new AgentConfig(this);
        }
    }
}
