package dev.aegis.agent.taint;

import java.util.IdentityHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The side table mapping application values to their taint.
 *
 * <p>Taint metadata cannot live on the value itself: {@code String} is final, and even if it
 * were not, adding a field to a JDK type would change application behaviour. So the agent
 * keeps an identity-keyed table alongside.
 *
 * <p>Three hard rules keep this from becoming a memory leak inside a customer's production
 * process, which is the fastest way to turn a security tool into an outage:
 *
 * <ul>
 *   <li>the table is <b>request-scoped</b> and released at request end, whatever the outcome;
 *   <li>it is <b>capped</b>, and stops tracking new values rather than growing without bound;
 *   <li>it uses <b>identity</b> semantics, because two equal strings are not the same value
 *       and conflating them would attribute one request's taint to another's data.
 * </ul>
 *
 * <p>Not thread-safe by design: an instance belongs to exactly one request on one thread, and
 * synchronising it would put a lock on the application's hot path.
 */
public final class TaintTracker {

    /** Per-request ceiling. Beyond this the tracker stops recording and flags an overflow. */
    public static final int MAX_TRACKED_VALUES = 10_000;

    private static final AtomicLong TOTAL_OVERFLOWS = new AtomicLong();

    private final Map<Object, TaintedValue> table = new IdentityHashMap<>();
    private final int capacity;
    private boolean overflowed;

    public TaintTracker() {
        this(MAX_TRACKED_VALUES);
    }

    public TaintTracker(int capacity) {
        this.capacity = capacity;
    }

    /**
     * Record taint for {@code value}.
     *
     * <p>Untainted values are not stored: an empty entry costs memory and answers no question
     * that {@link #taintOf} cannot answer by returning empty.
     */
    public void track(Object value, TaintedValue taint) {
        if (value == null || taint == null || !taint.isTainted()) {
            return;
        }
        if (table.size() >= capacity && !table.containsKey(value)) {
            if (!overflowed) {
                overflowed = true;
                TOTAL_OVERFLOWS.incrementAndGet();
            }
            return;
        }
        table.put(value, taint);
    }

    /** Never null — an untracked value is simply untainted. */
    public TaintedValue taintOf(Object value) {
        if (value == null) {
            return TaintedValue.empty();
        }
        TaintedValue taint = table.get(value);
        return taint == null ? TaintedValue.empty() : taint;
    }

    public boolean isTainted(Object value) {
        return taintOf(value).isTainted();
    }

    /** Mark a source's return value tainted end to end. */
    public void trackSource(String value, SourceKind kind, String name) {
        if (value == null || value.isEmpty()) {
            return;
        }
        track(value, TaintedValue.fullyTainted(value.length(), kind, name));
    }

    /**
     * True when the per-request cap was hit. Surfaced on the heartbeat as a coverage gap,
     * because silently under-reporting is worse than admitting a blind spot (ADR-0007).
     */
    public boolean hasOverflowed() {
        return overflowed;
    }

    public int size() {
        return table.size();
    }

    /**
     * True when nothing in this request is tainted yet.
     *
     * <p>The propagation hooks are inlined into {@code String} and {@code StringBuilder}, so
     * they fire for every concatenation the container, the framework and the driver perform —
     * thousands per request, of which only a handful ever touch attacker data. This is the
     * cheapest possible way to say "there is nothing to propagate": one field read against an
     * empty map, instead of two identity lookups that were always going to miss.
     */
    public boolean isEmpty() {
        return table.isEmpty();
    }

    /** Released at request end regardless of how the request finished. */
    public void clear() {
        table.clear();
        overflowed = false;
    }

    public static long totalOverflows() {
        return TOTAL_OVERFLOWS.get();
    }
}
