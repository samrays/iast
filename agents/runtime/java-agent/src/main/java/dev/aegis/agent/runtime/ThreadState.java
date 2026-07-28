package dev.aegis.agent.runtime;

/**
 * Everything the agent needs to know about the current thread, in one lookup.
 *
 * <p>Every hook asks two questions before doing anything: am I already inside agent code, and
 * is there a request in flight? Holding those in two separate {@link ThreadLocal}s meant two
 * map lookups on the hottest path in the product — and that path runs on every string
 * concatenation, every {@code StringBuilder.append} and every sink call in the entire process,
 * the container's and the framework's included. Collapsing them into a single mutable holder
 * halves the fixed cost of a hook that, in the overwhelmingly common case, goes on to do
 * nothing at all.
 *
 * <p>Fields are plain and unsynchronised on purpose: the holder belongs to exactly one thread.
 */
public final class ThreadState {

    private static final ThreadLocal<ThreadState> STATE =
            ThreadLocal.withInitial(ThreadState::new);

    /** True while agent code is on this thread's stack. */
    boolean inAgent;

    /** The request being served, or null outside one. */
    RequestContext context;

    private ThreadState() {}

    public static ThreadState current() {
        return STATE.get();
    }

    /**
     * Take the re-entrancy guard.
     *
     * <p>The agent's own code uses {@code String} and {@code StringBuilder} — exactly the
     * classes it instruments. Without this, a hook calls into the runtime, the runtime appends
     * to a builder, that append fires the hook again, and the process dies in
     * {@code StackOverflowError} — or, while a runtime class is still loading, in
     * {@code ClassCircularityError}.
     *
     * @return true when the caller took the guard and must release it
     */
    public boolean enter() {
        if (inAgent) {
            return false;
        }
        inAgent = true;
        return true;
    }

    public void exit() {
        inAgent = false;
    }

    /** The active request, or null. Callers must tolerate null. */
    public RequestContext context() {
        return context;
    }
}
