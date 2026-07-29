package dev.aegis.agent.taint;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * The set of tainted ranges over one value.
 *
 * <p>Immutable and normalized: ranges are kept sorted and merged, so equality is meaningful
 * and the wire representation is deterministic. Range sets are capped — pathological string
 * manipulation can otherwise fragment a value into thousands of one-character ranges and
 * turn an in-process security control into a memory leak (ADR-0007).
 */
public final class TaintedValue {

    /**
     * Beyond this, ranges collapse into a single covering range and the value is marked
     * imprecise. The finding is still correct — it just loses per-character highlighting,
     * which is a fair trade against unbounded growth in a customer's production heap.
     */
    public static final int MAX_RANGES = 32;

    private static final TaintedValue EMPTY = new TaintedValue(Collections.emptyList(), false);

    private final List<TaintRange> ranges;
    private final boolean imprecise;

    private TaintedValue(List<TaintRange> ranges, boolean imprecise) {
        this.ranges = ranges;
        this.imprecise = imprecise;
    }

    public static TaintedValue empty() {
        return EMPTY;
    }

    /** A value tainted end to end, as returned directly by a source. */
    public static TaintedValue fullyTainted(int length, SourceKind source, String sourceName) {
        if (length <= 0) {
            return EMPTY;
        }
        return new TaintedValue(
                List.of(new TaintRange(0, length, source, sourceName)), false);
    }

    public static TaintedValue of(List<TaintRange> ranges) {
        return normalize(ranges, false);
    }

    public List<TaintRange> ranges() {
        return ranges;
    }

    public boolean isTainted() {
        return !ranges.isEmpty();
    }

    /** True when ranges were collapsed to stay under the cap; highlighting is approximate. */
    public boolean isImprecise() {
        return imprecise;
    }

    public int rangeCount() {
        return ranges.size();
    }

    /**
     * True when any range overlapping {@code [from, to)} is still dangerous for {@code rule}.
     *
     * <p>This is the question a sink asks. Ranges that a sanitizer has cleared for this rule
     * class do not count, which is exactly what keeps a properly-escaped value from being
     * reported.
     */
    public boolean isDangerousIn(int from, int to, RuleClass rule) {
        for (TaintRange range : ranges) {
            if (range.overlaps(from, to) && !range.isSafeFor(rule)) {
                return true;
            }
        }
        return false;
    }

    public boolean isDangerousFor(RuleClass rule) {
        for (TaintRange range : ranges) {
            if (!range.isSafeFor(rule)) {
                return true;
            }
        }
        return false;
    }

    /** Ranges still dangerous for {@code rule} — the evidence attached to a finding. */
    public List<TaintRange> dangerousRanges(RuleClass rule) {
        List<TaintRange> result = new ArrayList<>();
        for (TaintRange range : ranges) {
            if (!range.isSafeFor(rule)) {
                result.add(range);
            }
        }
        return result;
    }

    // --- propagators -------------------------------------------------------------------

    /**
     * Concatenation: {@code left + right}.
     *
     * <p>The right operand's ranges shift by the left operand's length. Getting this wrong
     * is how an engine ends up highlighting the wrong characters and losing a developer's
     * trust the first time they look closely.
     */
    public static TaintedValue concat(
            TaintedValue left, int leftLength, TaintedValue right) {
        if (!left.isTainted() && !right.isTainted()) {
            return EMPTY;
        }
        List<TaintRange> combined = new ArrayList<>(left.ranges.size() + right.ranges.size());
        combined.addAll(left.ranges);
        for (TaintRange range : right.ranges) {
            combined.add(range.shift(leftLength));
        }
        return normalize(combined, left.imprecise || right.imprecise);
    }

    /** {@code substring(from, to)} — clip and rebase. */
    public TaintedValue substring(int from, int to) {
        if (!isTainted() || to <= from) {
            return EMPTY;
        }
        List<TaintRange> clipped = new ArrayList<>();
        for (TaintRange range : ranges) {
            TaintRange result = range.clip(from, to);
            if (result != null) {
                clipped.add(result);
            }
        }
        return normalize(clipped, imprecise);
    }

    /**
     * Insert {@code inserted} at {@code offset}, as {@code StringBuilder.insert} does.
     * Existing ranges at or after the offset move right by the inserted length.
     */
    public TaintedValue insert(int offset, TaintedValue inserted, int insertedLength) {
        List<TaintRange> result = new ArrayList<>();
        for (TaintRange range : ranges) {
            if (range.start() >= offset) {
                result.add(range.shift(insertedLength));
            } else if (range.end() <= offset) {
                result.add(range);
            } else {
                // The insertion splits this range; keep both halves rather than losing the
                // tail, which would under-report.
                TaintRange head = range.clip(range.start(), offset);
                if (head != null) {
                    result.add(head.shift(range.start()));
                }
                TaintRange tail = range.clip(offset, range.end());
                if (tail != null) {
                    result.add(tail.shift(offset + insertedLength));
                }
            }
        }
        for (TaintRange range : inserted.ranges) {
            result.add(range.shift(offset));
        }
        return normalize(result, imprecise || inserted.imprecise);
    }

    /**
     * Case folding, trimming to the same length, and similar length-preserving transforms.
     * Offsets are unchanged, so this is identity on the range set — but it exists as a named
     * operation because a propagator that silently dropped taint here would be a real bug.
     */
    public TaintedValue preservingTransform() {
        return this;
    }

    /**
     * A transform that rewrites the value wholesale — URL decoding, unescaping, normalization.
     *
     * <p>The output has no positional relationship to the input, so per-character offsets cannot
     * survive: {@code %3Cscript%3E} becoming {@code <script>} moves every character. The result
     * is therefore covered by a single range and marked <b>imprecise</b>, which is the honest
     * description — the agent knows the whole value derives from this source and no longer knows
     * which characters map where.
     *
     * <p>The alternative implementations are both worse. Keeping the old offsets would point a
     * developer at the wrong characters, and dropping the taint would lose the finding entirely —
     * and losing it silently, since decoding a parameter is what almost every handler does first.
     *
     * <p>Sanitization is preserved: a value that was HTML-escaped and then URL-decoded is still
     * not an XSS risk, and the cleared-for set is carried across.
     */
    public TaintedValue reshaped(int newLength) {
        if (!isTainted() || newLength <= 0) {
            return empty();
        }
        TaintRange first = ranges.get(0);
        java.util.Set<RuleClass> cleared = first.clearedFor();
        for (TaintRange range : ranges) {
            // The intersection, never the union: a rule only counts as sanitized if every part
            // of the value was sanitized for it. Taking the union here would launder taint.
            cleared = intersect(cleared, range.clearedFor());
        }
        return normalize(
                List.of(new TaintRange(0, newLength, first.source(), first.sourceName(), cleared)),
                true);
    }

    private static java.util.Set<RuleClass> intersect(
            java.util.Set<RuleClass> left, java.util.Set<RuleClass> right) {
        if (left.isEmpty() || right.isEmpty()) {
            return java.util.Set.of();
        }
        java.util.Set<RuleClass> both = new java.util.LinkedHashSet<>(left);
        both.retainAll(right);
        return both;
    }

    /**
     * {@code trim()} and friends: characters removed from the front shift everything left.
     */
    public TaintedValue trimmed(int removedFromStart, int newLength) {
        return substring(removedFromStart, removedFromStart + newLength);
    }

    /** Mark every range sanitized for {@code rule}. Other rule classes keep their taint. */
    public TaintedValue sanitizedFor(RuleClass rule) {
        if (!isTainted()) {
            return this;
        }
        List<TaintRange> cleared = new ArrayList<>(ranges.size());
        for (TaintRange range : ranges) {
            cleared.add(range.clearFor(rule));
        }
        return normalize(cleared, imprecise);
    }

    // --- normalization -----------------------------------------------------------------

    private static TaintedValue normalize(List<TaintRange> input, boolean imprecise) {
        if (input.isEmpty()) {
            return imprecise ? new TaintedValue(Collections.emptyList(), true) : EMPTY;
        }

        List<TaintRange> sorted = new ArrayList<>(input);
        sorted.sort(Comparator.comparingInt(TaintRange::start).thenComparingInt(TaintRange::end));

        List<TaintRange> merged = new ArrayList<>(sorted.size());
        TaintRange current = sorted.get(0);
        for (int i = 1; i < sorted.size(); i++) {
            TaintRange next = sorted.get(i);
            if (current.mergeableWith(next)) {
                current = current.mergeWith(next);
            } else {
                merged.add(current);
                current = next;
            }
        }
        merged.add(current);

        if (merged.size() <= MAX_RANGES) {
            return new TaintedValue(Collections.unmodifiableList(merged), imprecise);
        }
        return collapse(merged);
    }

    /**
     * Collapse to one covering range once the cap is exceeded.
     *
     * <p>The collapsed range keeps the first range's origin and only the rule classes cleared
     * across <em>every</em> component. Taking the union of {@code clearedFor} instead would
     * launder unsanitized taint into a "safe" range and cause a missed vulnerability — the
     * one failure mode this engine must never have.
     */
    private static TaintedValue collapse(List<TaintRange> merged) {
        TaintRange first = merged.get(0);
        int start = first.start();
        int end = first.end();
        java.util.EnumSet<RuleClass> commonCleared = java.util.EnumSet.noneOf(RuleClass.class);
        commonCleared.addAll(first.clearedFor());

        for (int i = 1; i < merged.size(); i++) {
            TaintRange range = merged.get(i);
            start = Math.min(start, range.start());
            end = Math.max(end, range.end());
            commonCleared.retainAll(range.clearedFor());
        }

        TaintRange covering =
                new TaintRange(start, end - start, first.source(), first.sourceName(), commonCleared);
        return new TaintedValue(List.of(covering), true);
    }

    @Override
    public String toString() {
        return "TaintedValue" + ranges + (imprecise ? " (imprecise)" : "");
    }
}
