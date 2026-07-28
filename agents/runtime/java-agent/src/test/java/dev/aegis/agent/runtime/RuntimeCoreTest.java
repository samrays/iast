package dev.aegis.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.aegis.agent.taint.SourceKind;
import dev.aegis.agent.taint.TaintTracker;
import dev.aegis.agent.taint.TaintedValue;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class RuntimeCoreTest {

    @AfterEach
    void clearContext() {
        RequestContext.end();
    }

    @Nested
    @DisplayName("taint tracker")
    class Tracker {

        @Test
        void tracksByIdentityNotEquality() {
            TaintTracker tracker = new TaintTracker();
            String tainted = new String("admin");
            String equalButDistinct = new String("admin");

            tracker.trackSource(tainted, SourceKind.PARAMETER, "user");

            assertTrue(tracker.isTainted(tainted));
            // Two equal strings are not the same value; conflating them would attribute one
            // request's taint to another request's data.
            assertFalse(tracker.isTainted(equalButDistinct));
        }

        @Test
        void untrackedValuesAreSimplyUntainted() {
            TaintTracker tracker = new TaintTracker();
            assertNotNull(tracker.taintOf("anything"));
            assertFalse(tracker.taintOf("anything").isTainted());
            assertFalse(tracker.taintOf(null).isTainted());
        }

        @Test
        void stopsGrowingAtCapacityAndFlagsTheGap() {
            TaintTracker tracker = new TaintTracker(4);
            for (int i = 0; i < 20; i++) {
                tracker.trackSource(new String("value" + i), SourceKind.PARAMETER, "q");
            }

            assertEquals(4, tracker.size());
            // An admitted blind spot beats an unbounded table in someone's production heap.
            assertTrue(tracker.hasOverflowed());
        }

        @Test
        void doesNotStoreUntaintedValues() {
            TaintTracker tracker = new TaintTracker();
            tracker.track("plain", TaintedValue.empty());
            assertEquals(0, tracker.size());
        }

        @Test
        void clearReleasesEverything() {
            TaintTracker tracker = new TaintTracker(2);
            tracker.trackSource(new String("a"), SourceKind.PARAMETER, "q");
            tracker.trackSource(new String("b"), SourceKind.PARAMETER, "q");
            tracker.trackSource(new String("c"), SourceKind.PARAMETER, "q");

            tracker.clear();

            assertEquals(0, tracker.size());
            assertFalse(tracker.hasOverflowed());
        }
    }

    @Nested
    @DisplayName("request context")
    class Context {

        @Test
        void isolatesRequestsPerThread() throws Exception {
            RequestContext outer = RequestContext.begin("trace-a", true);
            String value = new String("outer");
            outer.tracker().trackSource(value, SourceKind.PARAMETER, "q");

            AtomicInteger seenOnOtherThread = new AtomicInteger(-1);
            Thread other =
                    new Thread(
                            () -> {
                                RequestContext inner = RequestContext.current();
                                seenOnOtherThread.set(inner == null ? 0 : 1);
                            });
            other.start();
            other.join();

            assertEquals(0, seenOnOtherThread.get(), "context must not leak across threads");
            assertSame(outer, RequestContext.current());
        }

        @Test
        void endReleasesTheTableEvenAfterAnException() {
            RequestContext context = RequestContext.begin("trace-b", true);
            context.tracker().trackSource(new String("x"), SourceKind.PARAMETER, "q");

            try {
                throw new IllegalStateException("application blew up");
            } catch (IllegalStateException expected) {
                RequestContext.end();
            }

            // A stranded table on a pooled thread leaks memory and bleeds data between users.
            assertNull(RequestContext.current());
            assertEquals(0, context.tracker().size());
        }

        @Test
        void canBeAdoptedOnAnotherThreadForAsyncHandOffs() throws Exception {
            RequestContext context = RequestContext.begin("trace-c", true);
            String tainted = new String("payload");
            context.tracker().trackSource(tainted, SourceKind.PARAMETER, "q");

            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                boolean visible =
                        executor.submit(
                                        () -> {
                                            RequestContext.adopt(context);
                                            try {
                                                RequestContext active = RequestContext.current();
                                                return active != null
                                                        && active.tracker().isTainted(tainted);
                                            } finally {
                                                RequestContext.detach();
                                            }
                                        })
                                .get(5, TimeUnit.SECONDS);

                // Taint that vanishes at the first async boundary means silent under-reporting.
                assertTrue(visible);
            } finally {
                executor.shutdownNow();
            }
        }

        @Test
        void detachDoesNotClearTheOriginatingTable() {
            RequestContext context = RequestContext.begin("trace-d", true);
            String tainted = new String("payload");
            context.tracker().trackSource(tainted, SourceKind.PARAMETER, "q");

            RequestContext.detach();

            assertNull(RequestContext.current());
            assertTrue(context.tracker().isTainted(tainted));
        }
    }

    @Nested
    @DisplayName("bounded ring buffer")
    class Buffer {

        @Test
        void dropsOldestWhenFullAndNeverBlocks() {
            BoundedRingBuffer<String> buffer = new BoundedRingBuffer<>(3);
            for (String item : List.of("a", "b", "c", "d", "e")) {
                buffer.offer(item);
            }

            assertEquals(3, buffer.size());
            // During an incident the newest events are the ones worth keeping.
            assertEquals(List.of("c", "d", "e"), buffer.drain(10));
            assertEquals(2, buffer.droppedCount());
        }

        @Test
        void drainsOldestFirst() {
            BoundedRingBuffer<Integer> buffer = new BoundedRingBuffer<>(8);
            for (int i = 0; i < 5; i++) {
                buffer.offer(i);
            }

            assertEquals(List.of(0, 1, 2), buffer.drain(3));
            assertEquals(List.of(3, 4), buffer.drain(10));
            assertTrue(buffer.isEmpty());
        }

        @Test
        void rejectsNullAndZeroSizedDrains() {
            BoundedRingBuffer<String> buffer = new BoundedRingBuffer<>(2);
            assertFalse(buffer.offer(null));
            assertTrue(buffer.drain(0).isEmpty());
        }

        @Test
        void staysConsistentUnderConcurrentProducers() throws Exception {
            BoundedRingBuffer<Integer> buffer = new BoundedRingBuffer<>(512);
            int threads = 8;
            int perThread = 500;
            CountDownLatch start = new CountDownLatch(1);
            CountDownLatch done = new CountDownLatch(threads);
            ExecutorService executor = Executors.newFixedThreadPool(threads);

            try {
                for (int t = 0; t < threads; t++) {
                    executor.submit(
                            () -> {
                                try {
                                    start.await();
                                    for (int i = 0; i < perThread; i++) {
                                        buffer.offer(i);
                                    }
                                } catch (InterruptedException e) {
                                    Thread.currentThread().interrupt();
                                } finally {
                                    done.countDown();
                                }
                            });
                }
                start.countDown();
                assertTrue(done.await(30, TimeUnit.SECONDS));
            } finally {
                executor.shutdownNow();
            }

            // The invariant that matters: never above capacity, and every event either
            // accepted or counted as dropped.
            assertTrue(buffer.size() <= buffer.capacity());
            assertEquals(
                    (long) threads * perThread,
                    buffer.acceptedCount() + countLockContentionDrops(buffer));
        }

        private long countLockContentionDrops(BoundedRingBuffer<Integer> buffer) {
            // Offers rejected by tryLock never reach acceptedCount, so reconcile through the
            // drop counter's contention component.
            long accepted = buffer.acceptedCount();
            long dropped = buffer.droppedCount();
            long overCapacityDrops = Math.max(0, accepted - buffer.size());
            return Math.max(0, dropped - overCapacityDrops);
        }
    }

    @Nested
    @DisplayName("resource governor")
    class Governor {

        @Test
        void staysFullWhileInsideBudget() {
            ResourceGovernor governor = new ResourceGovernor(5.0);
            for (int i = 0; i < 20; i++) {
                governor.observe(1.0);
            }
            assertEquals(ResourceGovernor.Level.FULL, governor.level());
        }

        @Test
        void requiresSustainedBreachBeforeDegrading() {
            ResourceGovernor governor = new ResourceGovernor(5.0);

            governor.observe(9.0);
            governor.observe(9.0);
            // A single GC pause or traffic burst must not flap the agent.
            assertEquals(ResourceGovernor.Level.FULL, governor.level());

            governor.observe(9.0);
            assertEquals(ResourceGovernor.Level.SAMPLED, governor.level());
        }

        @Test
        void walksDownTheLadderUnderContinuedPressure() {
            ResourceGovernor governor = new ResourceGovernor(5.0);
            for (int i = 0; i < 9; i++) {
                governor.observe(9.0);
            }
            assertEquals(ResourceGovernor.Level.HEARTBEAT, governor.level());
            assertFalse(governor.level().allowsDataflow());
        }

        @Test
        void uninstallsImmediatelyOnAnEgregiousBreach() {
            ResourceGovernor governor = new ResourceGovernor(5.0);
            governor.observe(20.0);

            // At three times budget the agent is measurably harming the application; walking
            // the ladder would just prolong it.
            assertEquals(ResourceGovernor.Level.UNINSTALLED, governor.level());
        }

        @Test
        void recoversOnlyAfterSustainedCalm() {
            ResourceGovernor governor = new ResourceGovernor(5.0);
            for (int i = 0; i < 3; i++) {
                governor.observe(9.0);
            }
            assertEquals(ResourceGovernor.Level.SAMPLED, governor.level());

            for (int i = 0; i < 4; i++) {
                governor.observe(1.0);
            }
            assertEquals(ResourceGovernor.Level.SAMPLED, governor.level());

            governor.observe(1.0);
            assertEquals(ResourceGovernor.Level.FULL, governor.level());
        }

        @Test
        void doesNotRecoverJustBelowBudget() {
            ResourceGovernor governor = new ResourceGovernor(5.0);
            for (int i = 0; i < 3; i++) {
                governor.observe(9.0);
            }
            // 4.5 is under budget but above the recovery threshold — hovering there must not
            // oscillate the level.
            for (int i = 0; i < 20; i++) {
                governor.observe(4.5);
            }
            assertEquals(ResourceGovernor.Level.SAMPLED, governor.level());
        }

        @Test
        void neverClimbsBackOutOfUninstalledOnItsOwn() {
            ResourceGovernor governor = new ResourceGovernor(5.0);
            governor.observe(100.0);
            for (int i = 0; i < 50; i++) {
                governor.observe(0.0);
            }
            assertEquals(ResourceGovernor.Level.UNINSTALLED, governor.level());

            governor.reset();
            assertEquals(ResourceGovernor.Level.FULL, governor.level());
        }

        @Test
        void killSwitchTakesEffectImmediately() {
            ResourceGovernor governor = new ResourceGovernor(5.0);
            governor.disable();
            assertEquals(ResourceGovernor.Level.UNINSTALLED, governor.level());
            assertFalse(governor.level().allowsDataflow());
        }
    }
}
