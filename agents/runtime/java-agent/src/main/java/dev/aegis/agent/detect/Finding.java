package dev.aegis.agent.detect;

import dev.aegis.agent.taint.RuleClass;
import dev.aegis.agent.taint.TaintRange;
import java.util.List;

/** A confirmed dataflow from an untrusted source to a security-sensitive sink. */
public final class Finding {

    /**
     * How much the agent is prepared to claim.
     *
     * <p>The distinction matters commercially as much as technically: an IAST product that
     * reports {@code OBSERVED} flows as if they were confirmed injections is just a noisier
     * SAST, and loses the one advantage it has.
     */
    public enum Confidence {
        /** Reached the sink through a validator only — reported at reduced severity. */
        OBSERVED,
        /** Reached the sink with no sanitizer on the path. */
        CONFIRMED,
        /** Reached the sink and the payload matched an attack signature. */
        EXPLOITED
    }

    private final RuleClass rule;
    private final Confidence confidence;
    private final String sinkSignature;
    private final String sinkArgument;
    private final List<TaintRange> ranges;
    private final List<StackFrame> stack;
    private final String stackFingerprint;
    private final List<String> sanitizersApplied;
    private final List<String> validatorsApplied;
    private final boolean imprecise;

    Finding(
            RuleClass rule,
            Confidence confidence,
            String sinkSignature,
            String sinkArgument,
            List<TaintRange> ranges,
            List<StackFrame> stack,
            String stackFingerprint,
            List<String> sanitizersApplied,
            List<String> validatorsApplied,
            boolean imprecise) {
        this.rule = rule;
        this.confidence = confidence;
        this.sinkSignature = sinkSignature;
        this.sinkArgument = sinkArgument;
        this.ranges = List.copyOf(ranges);
        this.stack = List.copyOf(stack);
        this.stackFingerprint = stackFingerprint;
        this.sanitizersApplied = List.copyOf(sanitizersApplied);
        this.validatorsApplied = List.copyOf(validatorsApplied);
        this.imprecise = imprecise;
    }

    public RuleClass rule() {
        return rule;
    }

    public Confidence confidence() {
        return confidence;
    }

    /** {@code Class#method(descriptor)} — never a line number, so refactors do not resurrect. */
    public String sinkSignature() {
        return sinkSignature;
    }

    /** The value as it reached the sink, already redacted. */
    public String sinkArgument() {
        return sinkArgument;
    }

    public List<TaintRange> ranges() {
        return ranges;
    }

    public List<StackFrame> stack() {
        return stack;
    }

    public String stackFingerprint() {
        return stackFingerprint;
    }

    public List<String> sanitizersApplied() {
        return sanitizersApplied;
    }

    public List<String> validatorsApplied() {
        return validatorsApplied;
    }

    public boolean isImprecise() {
        return imprecise;
    }

    /** A validated-but-unsanitized flow is real, but not as loud as an unguarded one. */
    public RuleClass.Severity effectiveSeverity() {
        if (confidence == Confidence.OBSERVED) {
            return switch (rule.severity()) {
                case CRITICAL -> RuleClass.Severity.HIGH;
                case HIGH -> RuleClass.Severity.MEDIUM;
                case MEDIUM -> RuleClass.Severity.LOW;
                default -> RuleClass.Severity.INFO;
            };
        }
        return rule.severity();
    }

    @Override
    public String toString() {
        return "Finding[" + rule.key() + " " + confidence + " at " + sinkSignature + "]";
    }

    /** One application frame from the stack captured at the sink. */
    public record StackFrame(
            String declaringClass, String methodName, int lineNumber, boolean applicationCode) {}
}
