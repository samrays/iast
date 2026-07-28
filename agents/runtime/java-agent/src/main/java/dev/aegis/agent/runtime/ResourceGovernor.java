package dev.aegis.agent.runtime;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Keeps the agent inside its overhead budget by degrading itself.
 *
 * <p>The agent runs inside a business-critical process it does not own. The customer's
 * throughput matters more than our telemetry, always — so when overhead rises, the agent
 * gives up capability in ordered steps and, in the limit, removes itself entirely rather
 * than becoming the reason a production system is slow (docs/05 §6).
 *
 * <p>Degradation requires sustained breach and recovery requires sustained calm, so a single
 * garbage-collection pause or a burst of traffic cannot flap the agent between levels.
 */
public final class ResourceGovernor {

    /** Ordered from full capability to none. */
    public enum Level {
        /** Everything on. */
        FULL(0),
        /** Dataflow tracked on a fraction of requests. */
        SAMPLED(1),
        /** Dataflow off; configuration and dependency discovery continue. */
        CONFIG_ONLY(2),
        /** Detection off; the agent still heartbeats so the fleet view stays honest. */
        HEARTBEAT(3),
        /** The agent has removed itself from the request path. */
        UNINSTALLED(4);

        private final int rank;

        Level(int rank) {
            this.rank = rank;
        }

        public int rank() {
            return rank;
        }

        public boolean allowsDataflow() {
            return this == FULL || this == SAMPLED;
        }

        public String wireName() {
            return "GOVERNOR_LEVEL_" + name();
        }
    }

    /** Consecutive breaching samples before dropping a level. */
    static final int BREACH_SAMPLES_TO_DEGRADE = 3;
    /** Consecutive calm samples before recovering one level. */
    static final int CALM_SAMPLES_TO_RECOVER = 5;
    /** Recovery only begins below this fraction of the budget, to avoid oscillating. */
    static final double RECOVERY_FRACTION = 0.6;
    /** Sampling rate once degraded to {@link Level#SAMPLED}. */
    public static final double SAMPLED_RATE = 0.25;

    private final double budgetPct;
    private final AtomicInteger consecutiveBreaches = new AtomicInteger();
    private final AtomicInteger consecutiveCalm = new AtomicInteger();

    private volatile Level level = Level.FULL;
    private volatile double lastObservedPct;

    public ResourceGovernor(double budgetPct) {
        if (budgetPct <= 0) {
            throw new IllegalArgumentException("budget must be positive");
        }
        this.budgetPct = budgetPct;
    }

    public Level level() {
        return level;
    }

    public double budgetPct() {
        return budgetPct;
    }

    public double lastObservedPct() {
        return lastObservedPct;
    }

    /**
     * Feed one overhead sample and return the level now in force.
     *
     * <p>An egregious breach — three times the budget — skips the ladder and uninstalls
     * immediately. At that point the agent is measurably harming the application and a
     * graceful walk down the levels would just prolong it.
     */
    public Level observe(double observedPct) {
        lastObservedPct = observedPct;

        if (level == Level.UNINSTALLED) {
            return level;
        }

        if (observedPct > budgetPct * 3.0) {
            consecutiveBreaches.set(0);
            consecutiveCalm.set(0);
            level = Level.UNINSTALLED;
            return level;
        }

        if (observedPct > budgetPct) {
            consecutiveCalm.set(0);
            if (consecutiveBreaches.incrementAndGet() >= BREACH_SAMPLES_TO_DEGRADE) {
                consecutiveBreaches.set(0);
                level = next(level);
            }
            return level;
        }

        consecutiveBreaches.set(0);
        if (observedPct < budgetPct * RECOVERY_FRACTION) {
            if (consecutiveCalm.incrementAndGet() >= CALM_SAMPLES_TO_RECOVER) {
                consecutiveCalm.set(0);
                level = previous(level);
            }
        } else {
            consecutiveCalm.set(0);
        }
        return level;
    }

    /** True when this request should carry dataflow tracking at the current level. */
    public boolean shouldSample(java.util.random.RandomGenerator random) {
        return switch (level) {
            case FULL -> true;
            case SAMPLED -> random.nextDouble() < SAMPLED_RATE;
            default -> false;
        };
    }

    /** Remote kill switch: honoured within one heartbeat, without a restart. */
    public void disable() {
        level = Level.UNINSTALLED;
    }

    /** Used when the control plane re-enables an agent that was remotely disabled. */
    public void reset() {
        level = Level.FULL;
        consecutiveBreaches.set(0);
        consecutiveCalm.set(0);
    }

    private static Level next(Level current) {
        Level[] all = Level.values();
        int index = Math.min(current.rank() + 1, all.length - 1);
        return all[index];
    }

    private static Level previous(Level current) {
        // Never climbs back out of UNINSTALLED on its own: once the agent has removed itself
        // it stays out until an operator or the control plane says otherwise.
        if (current == Level.UNINSTALLED || current == Level.FULL) {
            return current;
        }
        return Level.values()[current.rank() - 1];
    }
}
