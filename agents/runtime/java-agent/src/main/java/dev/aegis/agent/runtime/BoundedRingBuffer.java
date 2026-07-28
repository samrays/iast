package dev.aegis.agent.runtime;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A fixed-capacity queue between the application thread and the reporting thread.
 *
 * <p>The defining property is what happens when it is full: it <b>drops</b>. It never blocks
 * and never grows. A security agent that stalls a request thread because its network is slow
 * has turned itself into an outage, and an agent that grows a queue without bound has turned
 * itself into an OOM. Losing telemetry is the only acceptable failure here, and the drop
 * count is reported on the heartbeat so the loss is visible rather than silent.
 *
 * <p>Drops the <em>oldest</em> entry rather than rejecting the newest: during an incident the
 * most recent events are the ones worth having.
 */
public final class BoundedRingBuffer<T> {

    private final Object[] slots;
    private final int capacity;
    private final ReentrantLock lock = new ReentrantLock();
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicLong accepted = new AtomicLong();

    private int head;
    private int size;

    public BoundedRingBuffer(int capacity) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("capacity must be positive");
        }
        this.capacity = capacity;
        this.slots = new Object[capacity];
    }

    /**
     * Offer an item. Never blocks.
     *
     * @return true if it was stored without discarding anything
     */
    public boolean offer(T item) {
        if (item == null) {
            return false;
        }
        // tryLock, not lock: even the brief contention of a busy drain must not park an
        // application thread. A failed acquisition costs one event, which is the cheaper loss.
        if (!lock.tryLock()) {
            dropped.incrementAndGet();
            return false;
        }
        try {
            if (size == capacity) {
                slots[head] = item;
                head = (head + 1) % capacity;
                dropped.incrementAndGet();
                accepted.incrementAndGet();
                return false;
            }
            slots[(head + size) % capacity] = item;
            size++;
            accepted.incrementAndGet();
            return true;
        } finally {
            lock.unlock();
        }
    }

    /** Take up to {@code max} items, oldest first. Called only by the reporting thread. */
    public List<T> drain(int max) {
        if (max <= 0) {
            return List.of();
        }
        lock.lock();
        try {
            int count = Math.min(max, size);
            List<T> batch = new ArrayList<>(count);
            for (int i = 0; i < count; i++) {
                int index = (head + i) % capacity;
                @SuppressWarnings("unchecked")
                T item = (T) slots[index];
                batch.add(item);
                slots[index] = null; // release the reference promptly
            }
            head = (head + count) % capacity;
            size -= count;
            return batch;
        } finally {
            lock.unlock();
        }
    }

    public int size() {
        lock.lock();
        try {
            return size;
        } finally {
            lock.unlock();
        }
    }

    public int capacity() {
        return capacity;
    }

    public boolean isEmpty() {
        return size() == 0;
    }

    /** Events lost to a full buffer or to lock contention. Surfaced on every heartbeat. */
    public long droppedCount() {
        return dropped.get();
    }

    public long acceptedCount() {
        return accepted.get();
    }
}
