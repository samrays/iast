package dev.aegis.agent.taint;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

/**
 * A contiguous span of a value that came from an untrusted source.
 *
 * <p>Taint is tracked as ranges rather than a boolean (ADR-0007). The difference is not
 * academic: a query built from a safe prefix plus one bound parameter and a query built by
 * concatenating a raw parameter are indistinguishable under boolean taint, so a boolean
 * engine either floods the user with false positives or misses real injections. Ranges also
 * let the console highlight the exact attacker-controlled characters inside the executed
 * statement, which is what makes a developer accept a finding on sight.
 *
 * <p>Immutable. Every propagator returns new ranges rather than mutating existing ones,
 * because the same {@code TaintedValue} may be referenced from several places in the
 * application and a shared mutation would corrupt all of them.
 */
public final class TaintRange {

    private final int start;
    private final int length;
    private final SourceKind source;
    private final String sourceName;
    /** Rule classes this range is no longer dangerous for, because a sanitizer cleared it. */
    private final Set<RuleClass> clearedFor;

    public TaintRange(int start, int length, SourceKind source, String sourceName) {
        this(start, length, source, sourceName, EnumSet.noneOf(RuleClass.class));
    }

    public TaintRange(
            int start, int length, SourceKind source, String sourceName, Set<RuleClass> clearedFor) {
        if (start < 0) {
            throw new IllegalArgumentException("start must not be negative: " + start);
        }
        if (length <= 0) {
            throw new IllegalArgumentException("length must be positive: " + length);
        }
        this.start = start;
        this.length = length;
        this.source = Objects.requireNonNull(source, "source");
        this.sourceName = sourceName == null ? "" : sourceName;
        this.clearedFor =
                clearedFor.isEmpty()
                        ? Collections.emptySet()
                        : Collections.unmodifiableSet(EnumSet.copyOf(clearedFor));
    }

    public int start() {
        return start;
    }

    public int length() {
        return length;
    }

    /** Exclusive. */
    public int end() {
        return start + length;
    }

    public SourceKind source() {
        return source;
    }

    public String sourceName() {
        return sourceName;
    }

    public Set<RuleClass> clearedFor() {
        return clearedFor;
    }

    /** True when a sanitizer for {@code rule} has been applied to this span. */
    public boolean isSafeFor(RuleClass rule) {
        return clearedFor.contains(rule);
    }

    /** Shift by {@code delta}, as concatenation does to the right-hand operand. */
    public TaintRange shift(int delta) {
        int newStart = start + delta;
        if (newStart < 0) {
            throw new IllegalArgumentException("shift would move the range before zero");
        }
        return new TaintRange(newStart, length, source, sourceName, clearedFor);
    }

    /**
     * Intersect with {@code [from, to)} and rebase to that window, as {@code substring} does.
     *
     * @return the clipped range, or {@code null} when nothing survives — the caller drops it.
     */
    public TaintRange clip(int from, int to) {
        int newStart = Math.max(start, from);
        int newEnd = Math.min(end(), to);
        if (newEnd <= newStart) {
            return null;
        }
        return new TaintRange(newStart - from, newEnd - newStart, source, sourceName, clearedFor);
    }

    /** Mark this span sanitized for {@code rule}; other rule classes keep their taint. */
    public TaintRange clearFor(RuleClass rule) {
        if (clearedFor.contains(rule)) {
            return this;
        }
        EnumSet<RuleClass> updated =
                clearedFor.isEmpty() ? EnumSet.noneOf(RuleClass.class) : EnumSet.copyOf(clearedFor);
        updated.add(rule);
        return new TaintRange(start, length, source, sourceName, updated);
    }

    /** True when this range shares at least one character with {@code [from, to)}. */
    public boolean overlaps(int from, int to) {
        return start < to && from < end();
    }

    /**
     * True when two ranges can be merged: adjacent or overlapping, same origin, and cleared
     * for the same rule classes. Merging ranges with different {@code clearedFor} sets would
     * silently launder taint from the unsanitized one.
     */
    boolean mergeableWith(TaintRange other) {
        return source == other.source
                && sourceName.equals(other.sourceName)
                && clearedFor.equals(other.clearedFor)
                && start <= other.end()
                && other.start <= end();
    }

    TaintRange mergeWith(TaintRange other) {
        int newStart = Math.min(start, other.start);
        int newEnd = Math.max(end(), other.end());
        return new TaintRange(newStart, newEnd - newStart, source, sourceName, clearedFor);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof TaintRange other)) {
            return false;
        }
        return start == other.start
                && length == other.length
                && source == other.source
                && sourceName.equals(other.sourceName)
                && clearedFor.equals(other.clearedFor);
    }

    @Override
    public int hashCode() {
        return Objects.hash(start, length, source, sourceName, clearedFor);
    }

    @Override
    public String toString() {
        return "TaintRange["
                + start
                + ".."
                + end()
                + " "
                + source
                + (sourceName.isEmpty() ? "" : ":" + sourceName)
                + (clearedFor.isEmpty() ? "" : " cleared=" + clearedFor)
                + "]";
    }
}
