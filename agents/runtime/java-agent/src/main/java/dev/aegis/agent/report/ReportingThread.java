package dev.aegis.agent.report;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * The single daemon thread that drains the buffer and talks to the network.
 *
 * <p>Daemon, so it can never keep the application's JVM alive. Low priority, so it yields to
 * request threads under load. And it is the <em>only</em> thread in the agent that performs
 * I/O — everything the application touches is a non-blocking enqueue.
 */
public final class ReportingThread implements Runnable {

    private static final int BATCH_SIZE = 512;

    private final Reporter reporter;
    private final Transport transport;
    private final long flushIntervalMillis;
    private final AtomicBoolean running = new AtomicBoolean(true);
    private Thread thread;

    public ReportingThread(Reporter reporter, Transport transport, long flushIntervalMillis) {
        this.reporter = reporter;
        this.transport = transport;
        this.flushIntervalMillis = flushIntervalMillis;
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
                Thread.sleep(flushIntervalMillis);
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

    /** Drain and send whatever is queued. Safe to call directly from a test. */
    public void flushOnce() {
        List<RuntimeEvent> batch = reporter.drain(BATCH_SIZE);
        while (!batch.isEmpty()) {
            transport.send(batch);
            batch = reporter.drain(BATCH_SIZE);
        }
    }

    /** Flush on shutdown so the last request's findings are not lost. */
    public void stop() {
        running.set(false);
        if (thread != null) {
            thread.interrupt();
        }
    }

    private static void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
