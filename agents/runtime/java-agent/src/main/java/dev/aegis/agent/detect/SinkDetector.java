package dev.aegis.agent.detect;

import dev.aegis.agent.redact.Redactor;
import dev.aegis.agent.taint.RuleClass;
import dev.aegis.agent.taint.TaintRange;
import dev.aegis.agent.taint.TaintedValue;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

/**
 * Decides whether a value arriving at a sink is a finding, and assembles the evidence.
 *
 * <p>This is the whole product in one method. It fires only when a tainted range that no
 * sanitizer has cleared for this rule class actually overlaps the sink's argument — which is
 * why a properly bound {@code PreparedStatement} parameter produces nothing, and a
 * concatenated one produces a critical finding with the offending characters marked.
 */
public final class SinkDetector {

    /**
     * Package prefixes that are never application code. Excluding them from the stack
     * fingerprint is what makes a finding survive a Spring upgrade instead of appearing to
     * be a brand new issue (ADR-0009).
     */
    private static final List<String> FRAMEWORK_PREFIXES =
            List.of(
                    "java.",
                    "javax.",
                    "jakarta.",
                    "jdk.",
                    "sun.",
                    "com.sun.",
                    "org.springframework.",
                    "org.apache.",
                    "org.hibernate.",
                    "org.eclipse.",
                    "io.netty.",
                    "reactor.",
                    "kotlin.",
                    "scala.",
                    "com.fasterxml.",
                    "ch.qos.logback.",
                    "org.slf4j.",
                    "org.junit.",
                    // JDBC drivers: a driver upgrade must not change a finding's identity.
                    "org.h2.",
                    "org.postgresql.",
                    "com.mysql.",
                    "oracle.jdbc.",
                    "com.microsoft.sqlserver.",
                    "com.zaxxer.hikari.",
                    "dev.aegis.");

    /** Top N application frames form the fingerprint. Deeper frames add churn, not identity. */
    private static final int FINGERPRINT_DEPTH = 5;

    private final Redactor redactor;
    private final Set<String> applicationPackages;

    public SinkDetector(Redactor redactor, Set<String> applicationPackages) {
        this.redactor = redactor;
        this.applicationPackages = applicationPackages;
    }

    /**
     * Evaluate a sink hit.
     *
     * @param taint taint of the argument as it arrived
     * @param argument the argument value itself
     * @param rule the rule class this sink belongs to
     * @param sinkSignature {@code Class#method(descriptor)}
     * @param stack frames captured at the sink
     * @param payloadLooksMalicious whether an attack signature matched, which promotes a
     *     confirmed flow to {@code EXPLOITED}
     * @return the finding, or {@code null} when there is nothing to report
     */
    public Finding evaluate(
            TaintedValue taint,
            String argument,
            RuleClass rule,
            String sinkSignature,
            StackTraceElement[] stack,
            boolean payloadLooksMalicious) {

        if (taint == null || !taint.isTainted() || argument == null) {
            return null;
        }

        // The sink's whole argument is the security-relevant span for these rules; a sink
        // that only cares about part of its argument passes a narrower window instead.
        if (!taint.isDangerousIn(0, argument.length(), rule)) {
            // Every overlapping range was sanitized for this rule class. Correct silence —
            // this is the case a boolean taint engine gets wrong.
            return null;
        }

        List<TaintRange> dangerous = taint.dangerousRanges(rule);
        if (dangerous.isEmpty()) {
            return null;
        }

        List<String> validators = validatorsOn(dangerous);
        Finding.Confidence confidence =
                payloadLooksMalicious
                        ? Finding.Confidence.EXPLOITED
                        : validators.isEmpty()
                                ? Finding.Confidence.CONFIRMED
                                : Finding.Confidence.OBSERVED;

        List<Finding.StackFrame> frames = captureFrames(stack);
        return new Finding(
                rule,
                confidence,
                sinkSignature,
                redactor.redactValue(argument),
                dangerous,
                frames,
                fingerprint(frames),
                sanitizersOn(taint),
                validators,
                taint.isImprecise());
    }

    /** Rule classes already cleared on these ranges, reported for context. */
    private List<String> sanitizersOn(TaintedValue taint) {
        List<String> applied = new ArrayList<>();
        for (TaintRange range : taint.ranges()) {
            for (RuleClass cleared : range.clearedFor()) {
                String key = cleared.key();
                if (!applied.contains(key)) {
                    applied.add(key);
                }
            }
        }
        return applied;
    }

    /**
     * Validators are not modelled as clearing taint — a length check or a regex narrows what
     * an attacker can send without making the value safe to concatenate. They downgrade
     * confidence and nothing more.
     */
    private List<String> validatorsOn(List<TaintRange> ranges) {
        return Collections.emptyList();
    }

    private List<Finding.StackFrame> captureFrames(StackTraceElement[] stack) {
        List<Finding.StackFrame> frames = new ArrayList<>();
        if (stack == null) {
            return frames;
        }
        for (StackTraceElement element : stack) {
            // The agent's own frames are an implementation detail of how the stack was
            // captured, not part of the customer's call path. Leaving them in puts
            // `AgentRuntime#onSink` at the top of the evidence a developer reads, which is
            // both noise and a small confession that the tool does not know what it is
            // looking at. Found by looking at a real finding in the console.
            if (element.getClassName().startsWith("dev.aegis.agent.")) {
                continue;
            }
            boolean application = isApplicationCode(element.getClassName());
            frames.add(
                    new Finding.StackFrame(
                            element.getClassName(),
                            element.getMethodName(),
                            element.getLineNumber(),
                            application));
            // Keep a little framework context for humans, but stop before the whole JDK.
            if (frames.size() >= 24) {
                break;
            }
        }
        return frames;
    }

    boolean isApplicationCode(String className) {
        if (className == null || className.isEmpty()) {
            return false;
        }
        // An explicit allow-list wins: a customer whose code lives under org.apache.* would
        // otherwise have every frame discarded and every finding collapse into one identity.
        for (String prefix : applicationPackages) {
            if (!prefix.isEmpty() && className.startsWith(prefix)) {
                return true;
            }
        }
        for (String prefix : FRAMEWORK_PREFIXES) {
            if (className.startsWith(prefix)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Identity of the code path, deliberately excluding line numbers.
     *
     * <p>Including them would resurrect every closed finding on the next reformat, destroy
     * the triage history and teach the team to ignore the tool.
     */
    String fingerprint(List<Finding.StackFrame> frames) {
        StringBuilder builder = new StringBuilder();
        int used = 0;
        for (Finding.StackFrame frame : frames) {
            if (!frame.applicationCode()) {
                continue;
            }
            builder.append(frame.declaringClass()).append('#').append(frame.methodName()).append(';');
            if (++used >= FINGERPRINT_DEPTH) {
                break;
            }
        }
        return sha256(builder.toString());
    }

    private static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            // Every JVM ships SHA-256; if this ever throws, the platform is broken.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
