package dev.aegis.agent.report;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

/**
 * A bounded, durable queue on disk for events the control plane could not accept.
 *
 * <p>The in-memory ring buffer absorbs a slow network for a few seconds. It cannot absorb a
 * control plane that is down for an hour, or a JVM that is restarted during a deploy while the
 * gateway is unreachable — and those are the moments when losing findings matters most,
 * because an outage on our side must not create a blind spot on the customer's.
 *
 * <p>Three properties make this safe to run inside someone else's production process:
 *
 * <ul>
 *   <li><b>Bounded.</b> A total byte ceiling, enforced by discarding the oldest segment. An
 *       unbounded spool would eventually fill the customer's disk, which is a far worse
 *       outcome than losing the oldest telemetry.
 *   <li><b>Segmented.</b> Events are replayed and deleted a whole file at a time, so a crash
 *       mid-replay re-sends a segment rather than corrupting one. The gateway deduplicates on
 *       event id, which is what makes an at-least-once transport correct rather than merely
 *       tolerable.
 *   <li><b>Single-threaded.</b> Only the reporting thread ever touches it. No locking, and no
 *       chance of an application thread blocking on disk I/O.
 * </ul>
 */
public final class Spool {

    /** Roll to a new segment past this size, so replay units stay small. */
    static final long SEGMENT_BYTES = 1024L * 1024L;

    private static final String PREFIX = "aegis-spool-";
    private static final String SUFFIX = ".ndjson";

    private final Path directory;
    private final long maxBytes;
    private long sequence;
    private long droppedEvents;
    private boolean disabled;

    public Spool(Path directory, long maxBytes) {
        this.directory = directory;
        this.maxBytes = Math.max(maxBytes, SEGMENT_BYTES);
    }

    /**
     * Persist a batch that could not be sent.
     *
     * <p>Failure disables the spool rather than propagating: a read-only volume or an exhausted
     * disk is the customer's problem to fix, and the agent's job at that point is to keep
     * quiet and keep the application running.
     */
    public void append(List<String> jsonLines) {
        if (disabled || jsonLines.isEmpty()) {
            return;
        }
        try {
            Files.createDirectories(directory);
            StringBuilder body = new StringBuilder(jsonLines.size() * 512);
            for (String line : jsonLines) {
                body.append(line).append('\n');
            }
            byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);

            Path target = currentSegment(bytes.length);
            Files.write(
                    target,
                    bytes,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.APPEND);
            enforceCeiling();
        } catch (IOException | RuntimeException e) {
            disabled = true;
        }
    }

    /** Segments awaiting replay, oldest first. Empty when there is nothing to resend. */
    public List<Path> pending() {
        if (disabled || !Files.isDirectory(directory)) {
            return List.of();
        }
        try (Stream<Path> files = Files.list(directory)) {
            return files.filter(Spool::isSegment)
                    .sorted(Comparator.comparing(path -> path.getFileName().toString()))
                    .toList();
        } catch (IOException e) {
            return List.of();
        }
    }

    /** Read one segment back. A segment that cannot be read is treated as empty and dropped. */
    public List<String> read(Path segment) {
        try {
            List<String> lines = new ArrayList<>();
            for (String line : Files.readAllLines(segment, StandardCharsets.UTF_8)) {
                if (!line.isBlank()) {
                    lines.add(line);
                }
            }
            return lines;
        } catch (IOException e) {
            return List.of();
        }
    }

    /** Delete a segment once the control plane has acknowledged it. */
    public void discard(Path segment) {
        try {
            Files.deleteIfExists(segment);
        } catch (IOException e) {
            // Left behind, and replayed once more on the next attempt. The gateway's
            // deduplication makes that harmless.
        }
    }

    /** Events thrown away because the ceiling was reached. Surfaced on the heartbeat. */
    public long droppedEvents() {
        return droppedEvents;
    }

    /** True once a write failed; the agent stops trying rather than retrying into a full disk. */
    public boolean isDisabled() {
        return disabled;
    }

    public long sizeBytes() {
        long total = 0;
        for (Path segment : pending()) {
            try {
                total += Files.size(segment);
            } catch (IOException ignored) {
                // Vanished between listing and sizing; it contributes nothing either way.
            }
        }
        return total;
    }

    private Path currentSegment(int incomingBytes) throws IOException {
        List<Path> segments = pending();
        if (!segments.isEmpty()) {
            Path newest = segments.get(segments.size() - 1);
            if (Files.size(newest) + incomingBytes <= SEGMENT_BYTES) {
                return newest;
            }
        }
        return directory.resolve(
                String.format("%s%013d-%04d%s", PREFIX, System.currentTimeMillis(), nextSequence(), SUFFIX));
    }

    private long nextSequence() {
        // Wraps at four digits, which is fine: the millisecond prefix keeps ordering correct
        // and only collides if 10,000 segments roll inside one millisecond.
        return (sequence = (sequence + 1) % 10_000);
    }

    /**
     * Discard the oldest segments until the spool fits.
     *
     * <p>Oldest first, deliberately. When a control plane has been unreachable long enough to
     * fill the spool, the freshest findings describe the code that is running now.
     */
    private void enforceCeiling() {
        List<Path> segments = pending();
        long total = 0;
        for (Path segment : segments) {
            try {
                total += Files.size(segment);
            } catch (IOException ignored) {
                // Treated as weightless rather than failing the whole sweep.
            }
        }
        for (Path segment : segments) {
            if (total <= maxBytes) {
                return;
            }
            long size;
            try {
                size = Files.size(segment);
            } catch (IOException e) {
                size = 0;
            }
            droppedEvents += read(segment).size();
            discard(segment);
            total -= size;
        }
    }

    private static boolean isSegment(Path path) {
        String name = path.getFileName().toString();
        return name.startsWith(PREFIX) && name.endsWith(SUFFIX);
    }
}
