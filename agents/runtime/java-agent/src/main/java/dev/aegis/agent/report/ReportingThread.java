package dev.aegis.agent.report;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * The single daemon thread that drains the buffer and talks to the network.
 *
 * <p>Daemon, so it can never keep the application's JVM alive. Low priority, so it yields to
 * request threads under load. And it is the <em>only</em> thread in the agent that performs
 * I/O — everything the application touches is a non-blocking enqueue.
 *
 * <p>It also owns the failure story. When the control plane is unreachable, batches go to the
 * {@link Spool} instead of being dropped, the retry interval backs off so a dead endpoint is
 * not hammered by every agent in the fleet at once, and the spool is replayed oldest-first as
 * soon as a send succeeds.
 */
public final class ReportingThread implements Runnable {

    private static final int BATCH_SIZE = 512;

    /** Ceiling on the backoff, so recovery is noticed soon after the endpoint returns. */
    static final int MAX_BACKOFF_MULTIPLIER = 64;

    /** Spool segments replayed per cycle, so a large backlog cannot starve live events. */
    static final int REPLAY_SEGMENTS_PER_CYCLE = 8;

    private final Reporter reporter;
    private final Transport transport;
    private final Spool spool;
    private final long flushIntervalMillis;
    private final AtomicBoolean running = new AtomicBoolean(true);

    private int backoffMultiplier = 1;
    private long spooledBatches;
    private long replayedBatches;
    private Thread thread;

    public ReportingThread(Reporter reporter, Transport transport, long flushIntervalMillis) {
        this(reporter, transport, flushIntervalMillis, null);
    }

    public ReportingThread(
            Reporter reporter, Transport transport, long flushIntervalMillis, Spool spool) {
        this.reporter = reporter;
        this.transport = transport;
        this.flushIntervalMillis = flushIntervalMillis;
        this.spool = spool;
    }

    public void start() {
        thread = new Thread(this, "aegis-reporter");
        thread.setDaemon(true);
        thread.setPriority(Thread.MIN_PRIORITY);
        thread.start();
    }

    @Override
    public void run() {
        while (running.get()) {
            try {
                flushOnce();
                Thread.sleep(flushIntervalMillis * backoffMultiplier);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Throwable t) {
                // Never let this thread die: an agent that stops reporting looks identical to
                // an application with no vulnerabilities, which is the worst failure mode
                // this product has.
                sleepQuietly(flushIntervalMillis);
            }
        }
        flushOnce();
    }

    /** Drain and send whatever is queued, then work through the spool. Safe to call from a test. */
    public void flushOnce() {
        boolean healthy = true;
        List<RuntimeEvent> batch = reporter.drain(BATCH_SIZE);
        while (!batch.isEmpty()) {
            if (!transport.send(batch)) {
                healthy = false;
                spool(batch);
            }
            batch = reporter.drain(BATCH_SIZE);
        }

        if (healthy) {
            healthy = replaySpool();
        }
        adjustBackoff(healthy);
    }

    /**
     * Replay spooled segments oldest-first.
     *
     * @return false as soon as the endpoint refuses again, leaving the rest for the next cycle
     */
    private boolean replaySpool() {
        if (spool == null) {
            return true;
        }
        int replayed = 0;
        for (Path segment : spool.pending()) {
            if (replayed >= REPLAY_SEGMENTS_PER_CYCLE) {
                break;
            }
            List<String> lines = spool.read(segment);
            if (!lines.isEmpty() && !transport.sendLines(lines)) {
                return false;
            }
            // Discarded only after acknowledgement. A crash between the two replays the
            // segment, which the gateway deduplicates on event id — an at-least-once transport
            // against an idempotent sink.
            spool.discard(segment);
            replayedBatches++;
            replayed++;
        }
        return true;
    }

    private void spool(List<RuntimeEvent> batch) {
        if (spool == null) {
            return;
        }
        List<String> lines = new ArrayList<>(batch.size());
        for (RuntimeEvent event : batch) {
            lines.add(event.toJson());
        }
        spool.append(lines);
        spooledBatches++;
    }

    /**
     * Double the interval on failure, snap straight back on success.
     *
     * <p>Asymmetric on purpose. Backing off gradually protects a control plane that is coming
     * back up from having the whole fleet reconnect at once; recovering gradually would only
     * delay findings the agent already holds.
     */
    private void adjustBackoff(boolean healthy) {
        backoffMultiplier = healthy ? 1 : Math.min(backoffMultiplier * 2, MAX_BACKOFF_MULTIPLIER);
    }

    /** Flush on shutdown so the last request's findings are not lost. */
    public void stop() {
        running.set(false);
        if (thread != null) {
            thread.interrupt();
        }
    }

    int backoffMultiplier() {
        return backoffMultiplier;
    }

    public long spooledBatches() {
        return spooledBatches;
    }

    public long replayedBatches() {
        return replayedBatches;
    }

    private static void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
