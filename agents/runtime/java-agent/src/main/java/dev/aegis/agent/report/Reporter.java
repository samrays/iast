package dev.aegis.agent.report;

import dev.aegis.agent.detect.Finding;
import dev.aegis.agent.runtime.BoundedRingBuffer;
import dev.aegis.agent.runtime.RequestContext;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Turns findings into events and hands them to the transport, without ever touching the
 * network from the thread that produced them.
 *
 * <p>The application thread's entire involvement is one non-blocking {@code offer} into a
 * bounded buffer. Everything after that — serialization, batching, HTTP, retries, spooling —
 * happens on a daemon thread the application does not own and cannot be delayed by.
 */
public final class Reporter {

    /** Ceiling on remembered routes and coverage gaps. */
    static final int MAX_ANNOUNCED = 4_096;

    private final BoundedRingBuffer<RuntimeEvent> buffer;
    private final AtomicLong sequence = new AtomicLong();

    /**
     * Facts already sent, so they are not sent again.
     *
     * <p>Concurrent because every request thread announces into it, and {@code add} returning
     * false is the deduplication — no lock, one atomic operation on a path that would otherwise
     * need one.
     */
    private final java.util.Set<String> announced = java.util.concurrent.ConcurrentHashMap.newKeySet();

    public Reporter(int capacity) {
        this.buffer = new BoundedRingBuffer<>(capacity);
    }

    /**
     * Queue a finding. Called on the application thread, so it must stay allocation-light and
     * must never block, throw or do I/O.
     */
    public void report(Finding finding, RequestContext context) {
        if (finding == null) {
            return;
        }
        buffer.offer(RuntimeEvent.taintHit(nextEventId(), finding, context));
    }

    /**
     * Queue a discovered route, for API inventory.
     *
     * <p>Emitted once per distinct route rather than once per request. A busy service handles
     * the same twenty routes millions of times a day; sending that as twenty million identical
     * events would drown the tenant's own findings in its ingest quota to tell the control
     * plane something it learned in the first second.
     */
    public void reportRoute(String method, String pathTemplate, boolean authenticated) {
        if (!firstSighting("route|" + method + "|" + pathTemplate + "|" + authenticated)) {
            return;
        }
        buffer.offer(RuntimeEvent.route(nextEventId(), method, pathTemplate, authenticated));
    }

    /**
     * Queue a place the agent knows it could not follow taint.
     *
     * <p>Reported rather than swallowed: an application with low instrumentation coverage and
     * zero findings must read as <em>unknown</em>, never as <em>secure</em> (ADR-0007).
     */
    public void reportCoverageGap(String reason, String component) {
        if (!firstSighting("gap|" + component + "|" + reason)) {
            return;
        }
        buffer.offer(RuntimeEvent.coverageGap(nextEventId(), reason, component));
    }

    /**
     * True the first time this key is seen.
     *
     * <p>Bounded, and it stops recording rather than evicting once full. Eviction would let a
     * pathological application — one that mints a distinct route per request id, say — cycle
     * the set forever and re-emit everything, which is the exact flood this exists to prevent.
     * Stopping instead costs a little inventory completeness and cannot cost availability.
     */
    private boolean firstSighting(String key) {
        if (announced.size() >= MAX_ANNOUNCED) {
            return false;
        }
        return announced.add(key);
    }

    /** Drain a batch for transmission. Called only by the reporting thread. */
    public List<RuntimeEvent> drain(int max) {
        return buffer.drain(max);
    }

    public int queued() {
        return buffer.size();
    }

    public long droppedCount() {
        return buffer.droppedCount();
    }

    public long acceptedCount() {
        return buffer.acceptedCount();
    }

    /**
     * A time-ordered, per-agent unique id.
     *
     * <p>The server deduplicates on this, which is what makes replaying the offline spool
     * safe after a reconnect — an at-least-once transport with an idempotent sink.
     */
    private String nextEventId() {
        return Long.toHexString(System.currentTimeMillis())
                + "-"
                + Long.toHexString(sequence.incrementAndGet());
    }
}
