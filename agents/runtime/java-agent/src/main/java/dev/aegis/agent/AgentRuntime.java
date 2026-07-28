package dev.aegis.agent;

import dev.aegis.agent.detect.Finding;
import dev.aegis.agent.detect.SinkDetector;
import dev.aegis.agent.redact.Redactor;
import dev.aegis.agent.report.Reporter;
import dev.aegis.agent.runtime.RequestContext;
import dev.aegis.agent.runtime.ResourceGovernor;
import dev.aegis.agent.taint.RuleClass;
import dev.aegis.agent.taint.TaintTracker;
import dev.aegis.agent.taint.TaintedValue;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The single static entry point every instrumented method calls into.
 *
 * <p>Advice code is inlined into the application's own methods, so it must be tiny and it
 * must be impossible for it to throw. Every public method here is wrapped: any internal
 * failure disables that hook, increments a counter and returns control to the application
 * immediately. There is no path in which an agent exception propagates into customer code —
 * that is the fail-open guarantee, and it is what makes this safe to run in production.
 */
public final class AgentRuntime {

    private static volatile AgentRuntime instance;

    /**
     * Re-entrancy guard.
     *
     * <p>The agent's own code uses {@code StringBuilder} and {@code String} — and those are
     * exactly the classes it instruments. Without this flag, a hook calls into the runtime,
     * the runtime appends to a builder, that append fires the hook again, and the process
     * dies in {@code StackOverflowError} (or, while a runtime class is still loading,
     * {@code ClassCircularityError}). Every hook checks it first and does nothing while
     * agent code is on the stack.
     *
     * <p>A plain {@code ThreadLocal} of {@code boolean[]} rather than {@code Boolean}: it is
     * allocated once per thread and read without boxing on the hottest path in the product.
     */
    private static final ThreadLocal<boolean[]> REENTRY = ThreadLocal.withInitial(() -> new boolean[1]);

    /** @return true when the caller took the guard and must call {@link #exit()} */
    private static boolean enter() {
        boolean[] flag = REENTRY.get();
        if (flag[0]) {
            return false;
        }
        flag[0] = true;
        return true;
    }

    private static void exit() {
        REENTRY.get()[0] = false;
    }

    private final SinkDetector detector;
    private final Reporter reporter;
    private final ResourceGovernor governor;
    private final Redactor redactor;
    private final AtomicLong hookFailures = new AtomicLong();
    private final AtomicLong sinksEvaluated = new AtomicLong();
    private final AtomicLong findingsReported = new AtomicLong();

    private AgentRuntime(
            Redactor redactor,
            java.util.Set<String> applicationPackages,
            int bufferCapacity,
            double cpuBudgetPct) {
        this.redactor = redactor;
        this.detector = new SinkDetector(redactor, applicationPackages);
        this.reporter = new Reporter(bufferCapacity);
        this.governor = new ResourceGovernor(cpuBudgetPct);
    }

    /**
     * Bootstrap entry point, invoked reflectively by {@code AegisAgent}.
     *
     * <p>Every parameter is a JDK type on purpose. This class lives on the bootstrap class
     * path and {@code AegisAgent} lives on the system path; if the signature named an agent
     * type such as {@code AgentConfig}, the two loaders would each define their own copy and
     * the call would fail to link. Passing only {@code String}, {@code int} and
     * {@code double} keeps the boundary clean.
     */
    public static void bootstrap(
            String[] redactKeys,
            String captureMode,
            int maxValueLength,
            String[] applicationPackages,
            int bufferCapacity,
            double cpuBudgetPct,
            String endpoint,
            String credential,
            long flushIntervalMillis) {

        Redactor.CaptureMode mode;
        try {
            mode = Redactor.CaptureMode.valueOf(captureMode);
        } catch (RuntimeException e) {
            // An unrecognised mode falls back to the safest option, never the most permissive.
            mode = Redactor.CaptureMode.NONE;
        }

        Redactor redactor =
                new Redactor(java.util.Set.of(redactKeys), mode, maxValueLength, false);
        AgentRuntime runtime =
                new AgentRuntime(
                        redactor,
                        java.util.Set.of(applicationPackages),
                        bufferCapacity,
                        cpuBudgetPct);
        install(runtime);
        warmClasses();

        dev.aegis.agent.report.Transport transport =
                dev.aegis.agent.report.Transport.forEndpoint(endpoint, credential);
        dev.aegis.agent.report.ReportingThread reporting =
                new dev.aegis.agent.report.ReportingThread(
                        runtime.reporter, transport, flushIntervalMillis);
        reporting.start();
        // Flush on the way out, so the last request's findings are not lost at shutdown.
        Runtime.getRuntime().addShutdownHook(new Thread(reporting::flushOnce, "aegis-flush"));
    }

    /**
     * Force every runtime class to load before instrumentation goes live.
     *
     * <p>A class defined lazily *while* a hook is executing triggers loading of the very
     * types the hook needs, which the JVM reports as {@code ClassCircularityError}. Touching
     * them up front costs microseconds once and removes the failure mode entirely.
     */
    private static void warmClasses() {
        try {
            RequestContext.end();
            TaintedValue warm =
                    TaintedValue.fullyTainted(1, dev.aegis.agent.taint.SourceKind.PARAMETER, "warm");
            warm.substring(0, 1);
            warm.sanitizedFor(RuleClass.SQL_INJECTION);
            new TaintTracker(1).taintOf(null);
            AttackSignatures.looksMalicious("warm", RuleClass.SQL_INJECTION);
            Finding.Confidence.values();
        } catch (Throwable ignored) {
            // Warming is an optimisation; failing it must not stop the agent installing.
        }
    }

    static void install(AgentRuntime runtime) {
        instance = runtime;
    }

    /** Null before bootstrap completes; advice must tolerate that and do nothing. */
    public static AgentRuntime get() {
        return instance;
    }

    public Reporter reporter() {
        return reporter;
    }

    public ResourceGovernor governor() {
        return governor;
    }

    public Redactor redactor() {
        return redactor;
    }

    public long hookFailures() {
        return hookFailures.get();
    }

    public long sinksEvaluated() {
        return sinksEvaluated.get();
    }

    public long findingsReported() {
        return findingsReported.get();
    }

    // --- source ------------------------------------------------------------------------

    /** Mark a value returned by a source as attacker-controllable. */
    public static void onSource(
            String value, dev.aegis.agent.taint.SourceKind kind, String name) {
        AgentRuntime runtime = instance;
        if (runtime == null || !enter()) {
            return;
        }
        if (runtime == null || !runtime.governor.level().allowsDataflow()) {
            return;
        }
        try {
            RequestContext context = RequestContext.current();
            if (context == null || !context.isSampled()) {
                return;
            }
            context.tracker().trackSource(value, kind, name);
            context.recordParameter(name, value);
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            exit();
        }
    }

    // --- propagators --------------------------------------------------------------------

    /**
     * {@code result = left + right} or {@code sb.append(right)}.
     *
     * <p>Called after the operation, with the concrete result, so the range arithmetic works
     * on the value that actually exists rather than on a prediction of it.
     */
    public static void onConcat(String result, Object left, Object right) {
        AgentRuntime runtime = instance;
        if (runtime == null || !enter()) {
            return;
        }
        if (runtime == null || result == null || !runtime.governor.level().allowsDataflow()) {
            return;
        }
        try {
            RequestContext context = RequestContext.current();
            if (context == null || !context.isSampled()) {
                return;
            }
            TaintTracker tracker = context.tracker();
            TaintedValue leftTaint = tracker.taintOf(left);
            TaintedValue rightTaint = tracker.taintOf(right);
            if (!leftTaint.isTainted() && !rightTaint.isTainted()) {
                return;
            }
            int leftLength = left == null ? 0 : String.valueOf(left).length();
            tracker.track(result, TaintedValue.concat(leftTaint, leftLength, rightTaint));
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            exit();
        }
    }

    /**
     * {@code StringBuilder.append(x)} — the builder itself carries the accumulated taint.
     *
     * <p>Taint is keyed on the builder object, not on any intermediate string, so a query
     * assembled across a dozen appends and materialized once by {@code toString()} still
     * arrives at the sink with correct offsets.
     *
     * @param contentBefore the builder's content prior to this append, captured on entry
     */
    public static void onBuilderAppend(Object builder, String contentBefore, Object appended) {
        AgentRuntime runtime = instance;
        if (runtime == null || !enter()) {
            return;
        }
        if (runtime == null || builder == null || !runtime.governor.level().allowsDataflow()) {
            return;
        }
        try {
            RequestContext context = RequestContext.current();
            if (context == null || !context.isSampled()) {
                return;
            }
            TaintTracker tracker = context.tracker();
            TaintedValue appendedTaint = tracker.taintOf(appended);
            TaintedValue builderTaint = tracker.taintOf(builder);
            if (!appendedTaint.isTainted() && !builderTaint.isTainted()) {
                return;
            }
            int lengthBefore = contentBefore == null ? 0 : contentBefore.length();
            tracker.track(builder, TaintedValue.concat(builderTaint, lengthBefore, appendedTaint));
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            exit();
        }
    }

    /**
     * Bind the current request context to a task that is about to run on another thread.
     *
     * <p>Returns the original task unchanged when there is nothing to carry, so the common
     * case adds no wrapper and no allocation to the application's executor.
     */
    public static Runnable wrapForHandoff(Runnable task) {
        AgentRuntime runtime = instance;
        if (runtime == null || task == null) {
            return task;
        }
        if (!enter()) {
            return task;
        }
        try {
            RequestContext context = RequestContext.current();
            if (context == null) {
                return task;
            }
            return () -> {
                RequestContext.adopt(context);
                try {
                    task.run();
                } finally {
                    // Detach, never end: the originating thread still owns the taint table.
                    RequestContext.detach();
                }
            };
        } catch (Throwable t) {
            runtime.hookFailed(t);
            return task;
        } finally {
            exit();
        }
    }

    /** A length-preserving transform such as {@code toUpperCase} or {@code intern}. */
    public static void onPreservingTransform(String result, Object source) {
        AgentRuntime runtime = instance;
        if (runtime == null || !enter()) {
            return;
        }
        if (runtime == null || result == null) {
            return;
        }
        try {
            RequestContext context = RequestContext.current();
            if (context == null || !context.isSampled()) {
                return;
            }
            TaintTracker tracker = context.tracker();
            TaintedValue taint = tracker.taintOf(source);
            if (taint.isTainted()) {
                tracker.track(result, taint.preservingTransform());
            }
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            exit();
        }
    }

    /** {@code source.substring(from, to)}. */
    public static void onSubstring(String result, Object source, int from, int to) {
        AgentRuntime runtime = instance;
        if (runtime == null || !enter()) {
            return;
        }
        if (runtime == null || result == null) {
            return;
        }
        try {
            RequestContext context = RequestContext.current();
            if (context == null || !context.isSampled()) {
                return;
            }
            TaintTracker tracker = context.tracker();
            TaintedValue taint = tracker.taintOf(source);
            if (taint.isTainted()) {
                tracker.track(result, taint.substring(from, to));
            }
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            exit();
        }
    }

    /**
     * A sanitizer ran: clear the value for that rule class only.
     *
     * <p>Binding a {@code PreparedStatement} parameter goes through here, which is precisely
     * why a parameterised query produces no finding while a concatenated one does.
     */
    public static void onSanitized(String result, Object source, RuleClass rule) {
        AgentRuntime runtime = instance;
        if (runtime == null || !enter()) {
            return;
        }
        if (runtime == null || result == null) {
            return;
        }
        try {
            RequestContext context = RequestContext.current();
            if (context == null) {
                return;
            }
            TaintTracker tracker = context.tracker();
            TaintedValue taint = tracker.taintOf(source);
            if (taint.isTainted()) {
                tracker.track(result, taint.sanitizedFor(rule));
            }
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            exit();
        }
    }

    // --- sinks --------------------------------------------------------------------------

    /**
     * A security-sensitive operation is about to run with {@code argument}.
     *
     * @return the finding if one was reported, so blocking mode can act on it. Monitor mode
     *     ignores the return value entirely.
     */
    public static Finding onSink(Object argument, RuleClass rule, String sinkSignature) {
        AgentRuntime runtime = instance;
        if (runtime == null || !(argument instanceof String value)) {
            return null;
        }
        if (!enter()) {
            return null;
        }
        if (!runtime.governor.level().allowsDataflow()) {
            return null;
        }
        try {
            RequestContext context = RequestContext.current();
            if (context == null || !context.isSampled()) {
                return null;
            }
            runtime.sinksEvaluated.incrementAndGet();

            TaintedValue taint = context.tracker().taintOf(argument);
            if (!taint.isTainted()) {
                return null;
            }

            Finding finding =
                    runtime.detector.evaluate(
                            taint,
                            value,
                            rule,
                            sinkSignature,
                            // Skip this frame and the advice frame; the caller is what matters.
                            new Throwable().getStackTrace(),
                            AttackSignatures.looksMalicious(value, rule));
            if (finding != null) {
                runtime.findingsReported.incrementAndGet();
                runtime.reporter.report(finding, context);
            }
            return finding;
        } catch (Throwable t) {
            runtime.hookFailed(t);
            return null;
        } finally {
            exit();
        }
    }

    /**
     * Record an internal failure and keep going.
     *
     * <p>Deliberately silent by default. An agent that logs a stack trace on every hook
     * failure can turn a small bug into a log-volume incident in the customer's environment.
     */
    void hookFailed(Throwable t) {
        hookFailures.incrementAndGet();
        if (Boolean.getBoolean("aegis.debug")) {
            System.err.println("[aegis] hook failed: " + t);
        }
    }
}
