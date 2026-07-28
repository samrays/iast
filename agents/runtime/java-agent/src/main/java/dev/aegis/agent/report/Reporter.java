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

    private final BoundedRingBuffer<RuntimeEvent> buffer;
    private final AtomicLong sequence = new AtomicLong();

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

    /** Queue a discovered route, for API inventory. */
    public void reportRoute(String method, String pathTemplate, boolean authenticated) {
        buffer.offer(RuntimeEvent.route(nextEventId(), method, pathTemplate, authenticated));
    }

    /**
     * Queue a place the agent knows it could not follow taint.
     *
     * <p>Reported rather than swallowed: an application with low instrumentation coverage and
     * zero findings must read as <em>unknown</em>, never as <em>secure</em> (ADR-0007).
     */
    public void reportCoverageGap(String reason, String component) {
        buffer.offer(RuntimeEvent.coverageGap(nextEventId(), reason, component));
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
