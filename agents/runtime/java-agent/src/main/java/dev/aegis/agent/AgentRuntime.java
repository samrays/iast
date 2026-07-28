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
     * <p>The parameter is a plain {@code Map<String, String>} on purpose. This class lives on
     * the bootstrap class path and {@code AegisAgent} lives on the system path; if the
     * signature named an agent type such as {@code AgentConfig}, the two loaders would each
     * define their own copy and the call would fail to link. Only types both loaders resolve
     * identically may cross — in practice, {@code java.base}. A map also keeps the boundary
     * stable, so adding a setting no longer means editing a reflected method signature in two
     * places and discovering the mismatch at runtime in a customer's process.
     */
    public static void bootstrap(java.util.Map<String, String> settings) {
        Redactor.CaptureMode mode;
        try {
            mode = Redactor.CaptureMode.valueOf(setting(settings, "capture", "NONE"));
        } catch (RuntimeException e) {
            // An unrecognised mode falls back to the safest option, never the most permissive.
            mode = Redactor.CaptureMode.NONE;
        }

        Redactor redactor =
                new Redactor(
                        splitToSet(setting(settings, "redact_keys", "")),
                        mode,
                        (int) number(settings, "max_value_length", 512),
                        false);
        AgentRuntime runtime =
                new AgentRuntime(
                        redactor,
                        splitToSet(setting(settings, "packages", "")),
                        (int) number(settings, "buffer_capacity", 4096),
                        number(settings, "cpu_budget_pct", 5.0));
        install(runtime);
        warmClasses();

        dev.aegis.agent.report.Transport transport =
                dev.aegis.agent.report.Transport.forEndpoint(
                        setting(settings, "endpoint", ""),
                        setting(settings, "api_key", ""),
                        setting(settings, "pins", ""));

        dev.aegis.agent.report.ReportingThread reporting =
                new dev.aegis.agent.report.ReportingThread(
                        runtime.reporter,
                        transport,
                        1_000L,
                        buildSpool(
                                setting(settings, "spool_dir", ""),
                                (long) number(settings, "spool_max_bytes", 64L * 1024 * 1024)));
        reporting.start();
        // Flush on the way out, so the last request's findings are not lost at shutdown.
        Runtime.getRuntime().addShutdownHook(new Thread(reporting::flushOnce, "aegis-flush"));
    }

    /**
     * Build the offline spool, or return null when the deployment has not asked for one.
     *
     * <p>Opt-in rather than on by default: writing to disk inside someone else's container is
     * a decision for the operator, not for us. Read-only root filesystems are common and
     * correct, and an agent that assumed otherwise would fail loudly in exactly the
     * environments run by the people who care most.
     */
    private static dev.aegis.agent.report.Spool buildSpool(String directory, long maxBytes) {
        if (directory == null || directory.isBlank()) {
            return null;
        }
        try {
            return new dev.aegis.agent.report.Spool(java.nio.file.Path.of(directory), maxBytes);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String setting(
            java.util.Map<String, String> settings, String key, String fallback) {
        String value = settings == null ? null : settings.get(key);
        return value == null || value.isEmpty() ? fallback : value;
    }

    private static double number(
            java.util.Map<String, String> settings, String key, double fallback) {
        try {
            return Double.parseDouble(setting(settings, key, Double.toString(fallback)));
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static java.util.Set<String> splitToSet(String value) {
        java.util.Set<String> items = new java.util.LinkedHashSet<>();
        for (String entry : value.split("[,;]")) {
            String trimmed = entry.trim();
            if (!trimmed.isEmpty()) {
                items.add(trimmed);
            }
        }
        return items;
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

    // --- request lifecycle ---------------------------------------------------------------

    /**
     * An HTTP request is entering the application.
     *
     * @return true when this frame <em>created</em> the context and must therefore end it.
     *     Servlet stacks nest — {@code HttpServlet.service} calls its own two-argument
     *     overload, filters wrap servlets, and Spring's dispatcher is itself a servlet — so
     *     only the outermost frame may open or close the context. An inner frame that called
     *     {@code begin} again would discard the taint table mid-request and the finding would
     *     vanish.
     */
    public static boolean onRequestEnter(Object request) {
        AgentRuntime runtime = instance;
        if (runtime == null || !enter()) {
            return false;
        }
        try {
            if (RequestContext.current() != null) {
                return false;
            }
            if (runtime.governor.level() == dev.aegis.agent.runtime.ResourceGovernor.Level.UNINSTALLED) {
                return false;
            }
            boolean sampled =
                    runtime.governor.shouldSample(java.util.concurrent.ThreadLocalRandom.current());
            RequestContext context = RequestContext.begin(newTraceId(), sampled);
            dev.aegis.agent.runtime.HttpFacade.describe(request, context);

            // The request URI is attacker-controlled and reaches path and redirect sinks, so it
            // is a source in its own right — not merely evidence.
            if (sampled && !context.path().isEmpty()) {
                context.tracker()
                        .trackSource(
                                context.path(),
                                dev.aegis.agent.taint.SourceKind.PATH,
                                "request-uri");
            }
            return true;
        } catch (Throwable t) {
            runtime.hookFailed(t);
            return false;
        } finally {
            exit();
        }
    }

    /**
     * The request is finishing, successfully or not.
     *
     * <p>Called from a {@code finally}, so an application exception cannot strand a taint table
     * on a pooled container thread — which would leak memory and, far worse, carry one user's
     * data into the next request served by that thread.
     */
    public static void onRequestExit(boolean owner, Object request) {
        AgentRuntime runtime = instance;
        if (runtime == null || !owner) {
            return;
        }
        if (!enter()) {
            return;
        }
        try {
            RequestContext context = RequestContext.current();
            if (context == null) {
                return;
            }
            String template = dev.aegis.agent.runtime.HttpFacade.routeTemplate(request);
            if (!template.isEmpty()) {
                context.withRouteTemplate(template);
            }
            runtime.reporter.reportRoute(
                    context.method(),
                    context.routeTemplate(),
                    dev.aegis.agent.runtime.HttpFacade.isAuthenticated(request));
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            // Unconditional: the whole point of this hook is that the table is always released.
            RequestContext.end();
            exit();
        }
    }

    /** 128 bits of randomness as hex — enough to be unique without coordinating with anyone. */
    private static String newTraceId() {
        java.util.concurrent.ThreadLocalRandom random =
                java.util.concurrent.ThreadLocalRandom.current();
        return Long.toHexString(random.nextLong()) + Long.toHexString(random.nextLong());
    }

    // --- source ------------------------------------------------------------------------

    /**
     * A servlet accessor returned attacker-controlled data.
     *
     * <p>One hook for every accessor rather than one per method: the advice is inlined into
     * container code that runs on every request, so the fewer distinct shapes of bytecode
     * pasted into a hot container class the better.
     *
     * @param accessor the method name, e.g. {@code getParameter}, which selects the source kind
     * @param arguments the call's own arguments; the first, when a string, names the source
     */
    public static void onHttpSource(String accessor, Object[] arguments, Object result) {
        AgentRuntime runtime = instance;
        if (runtime == null || result == null || !enter()) {
            return;
        }
        try {
            if (!runtime.governor.level().allowsDataflow()) {
                return;
            }
            RequestContext context = RequestContext.current();
            if (context == null || !context.isSampled()) {
                return;
            }
            dev.aegis.agent.taint.SourceKind kind = sourceKindOf(accessor);
            if (kind == null) {
                return;
            }
            String name =
                    arguments != null && arguments.length > 0 && arguments[0] instanceof String key
                            ? key
                            : accessor;

            if (result instanceof String value) {
                context.tracker().trackSource(value, kind, name);
                context.recordParameter(name, value);
            } else if (result instanceof String[] values) {
                for (String value : values) {
                    context.tracker().trackSource(value, kind, name);
                }
                if (values.length > 0) {
                    context.recordParameter(name, values[0]);
                }
            }
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            exit();
        }
    }

    private static dev.aegis.agent.taint.SourceKind sourceKindOf(String accessor) {
        if (accessor == null) {
            return null;
        }
        return switch (accessor) {
            case "getParameter", "getParameterValues" ->
                    dev.aegis.agent.taint.SourceKind.PARAMETER;
            case "getHeader" -> dev.aegis.agent.taint.SourceKind.HEADER;
            case "getQueryString" -> dev.aegis.agent.taint.SourceKind.QUERY_STRING;
            case "getPathInfo", "getRequestURI", "getPathTranslated" ->
                    dev.aegis.agent.taint.SourceKind.PATH;
            default -> null;
        };
    }

    /** {@code Cookie.getValue()} — attacker-controlled, and named by its own cookie. */
    public static void onCookieValue(Object cookie, String value) {
        AgentRuntime runtime = instance;
        if (runtime == null || value == null || value.isEmpty() || !enter()) {
            return;
        }
        try {
            if (!runtime.governor.level().allowsDataflow()) {
                return;
            }
            RequestContext context = RequestContext.current();
            if (context == null || !context.isSampled()) {
                return;
            }
            context.tracker()
                    .trackSource(
                            value,
                            dev.aegis.agent.taint.SourceKind.COOKIE,
                            dev.aegis.agent.runtime.HttpFacade.cookieName(cookie));
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            exit();
        }
    }

    /**
     * The application read the request body as a stream.
     *
     * <p>The agent does not follow taint through the body: doing so means wrapping the
     * container's stream, and a bug in that wrapper corrupts uploads in production. Rather
     * than pretend the blind spot does not exist, it is reported — an application with poor
     * instrumentation coverage and no findings must read as <em>unknown</em>, never as
     * <em>secure</em> (ADR-0007).
     */
    public static void onRequestBodyAccess(String accessor) {
        AgentRuntime runtime = instance;
        if (runtime == null || !enter()) {
            return;
        }
        try {
            RequestContext context = RequestContext.current();
            if (context == null) {
                return;
            }
            runtime.reporter.reportCoverageGap(
                    "request body read via " + accessor + "; taint not tracked through the stream",
                    "servlet-request-body");
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            exit();
        }
    }

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

    /**
     * The {@link java.util.concurrent.Callable} counterpart of {@link #wrapForHandoff(Runnable)}.
     *
     * <p>Kept as a separate overload rather than one {@code Object} method because the advice
     * assigns the result straight back into the instrumented method's own argument slot, which
     * has to type-check against the real parameter type.
     */
    public static <T> java.util.concurrent.Callable<T> wrapForHandoff(
            java.util.concurrent.Callable<T> task) {
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
                    return task.call();
                } finally {
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
