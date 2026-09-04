package dev.aegis.agent;

import dev.aegis.agent.detect.Finding;
import dev.aegis.agent.detect.SinkDetector;
import dev.aegis.agent.redact.Redactor;
import dev.aegis.agent.report.Reporter;
import dev.aegis.agent.runtime.RequestContext;
import dev.aegis.agent.runtime.ResourceGovernor;
import dev.aegis.agent.runtime.ThreadState;
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
        ThreadState state = ThreadState.current();
        if (runtime == null || !state.enter()) {
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
            // `context.path()` — the raw request URI — is recorded as evidence (the request
            // line a finding's occurrence is attached to) but deliberately not tracked as taint
            // here. It used to be, on the theory that it "reaches path and redirect sinks", but
            // the URI includes the context path — fixed at deploy time, identical on every
            // request — and every framework reads it for structural reasons that have nothing
            // to do with the current request's attacker-controlled parts. Thymeleaf resolving
            // its own `@{...}` resource links did exactly that and produced a reflected-xss
            // finding on WebGoat's own favicon and stylesheets, on every page, from the first
            // request. See AgentRuntime#sourceKindOf for the matching fix on the accessor side.
            dev.aegis.agent.runtime.HttpFacade.describe(request, context);
            return true;
        } catch (Throwable t) {
            runtime.hookFailed(t);
            return false;
        } finally {
            state.exit();
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
        ThreadState state = ThreadState.current();
        if (runtime == null || !owner) {
            return;
        }
        if (!state.enter()) {
            return;
        }
        try {
            RequestContext context = state.context();
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
            state.exit();
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
        ThreadState state = ThreadState.current();
        if (runtime == null || result == null || !state.enter()) {
            return;
        }
        try {
            if (!runtime.governor.level().allowsDataflow()) {
                return;
            }
            RequestContext context = state.context();
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
            state.exit();
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
            // getPathInfo/getPathTranslated: the extra path segment past the servlet mapping,
            // the classic path-traversal source (`new File(base, request.getPathInfo())`).
            //
            // getRequestURI deliberately excluded, and not merely renamed into this group: it
            // returns the *whole* URI, context path included, and every web framework reads it
            // for entirely mundane, non-attacker-facing reasons — resolving a template's own
            // `@{...}` resource links being the one that actually happened here. Real requests
            // to a real deployment differ from each other in query string, headers, parameters
            // and the trailing path segments a route captures — never in the context path,
            // which is fixed at deploy time. Treating it as untrusted taints server config, not
            // attacker input, and the result was a reflected-xss finding firing on WebGoat's
            // own favicon and stylesheet links, on every single page, from the first request.
            case "getPathInfo", "getPathTranslated" -> dev.aegis.agent.taint.SourceKind.PATH;
            default -> null;
        };
    }

    /** {@code Cookie.getValue()} — attacker-controlled, and named by its own cookie. */
    public static void onCookieValue(Object cookie, String value) {
        AgentRuntime runtime = instance;
        ThreadState state = ThreadState.current();
        if (runtime == null || value == null || value.isEmpty() || !state.enter()) {
            return;
        }
        try {
            if (!runtime.governor.level().allowsDataflow()) {
                return;
            }
            RequestContext context = state.context();
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
            state.exit();
        }
    }

    /**
     * The application read the request body as a stream: {@code getInputStream()} or
     * {@code getReader()}.
     *
     * <p>This does not wrap the container's stream — that risk (a bug in the wrapper corrupting
     * a real upload in production) is exactly why this was a declared blind spot before. What
     * changed is narrower: the stream <em>object itself</em> is marked in the same
     * identity-keyed side table every other object-sourced value already uses (see
     * {@link #onDerivedObject}), never touching the bytes flowing through it. A propagator that
     * later derives a concrete value from this exact object — {@code readAllBytes()},
     * {@code new String(bytes, charset)}, Spring's {@code StreamUtils.copyToString} — carries
     * the mark forward the same way {@code ByteArrayInputStream(byte[])} already does for
     * deserialization. One more link turned out to matter in practice, confirmed by tracing a
     * real request rather than assumed: Spring wraps the stream in a {@code PushbackInputStream}
     * before reading it (content-type sniffing peeks at the first bytes), which is a *different*
     * object from the one this method marks — so that constructor needs its own propagator too,
     * or the mark never reaches {@code copyToString} at all.
     *
     * <p>The one honest cost: at this point the real content length is not yet known — nothing
     * has read the stream yet. The mark uses a placeholder length of 1, which is sufficient for
     * every existing dangerousness check (an overlap test against {@code [0, realLength)}), and
     * is recorded {@link TaintedValue#isImprecise() imprecise} so a finding's evidence does not
     * claim character-level precision it does not have. Reading the body through anything not
     * explicitly propagated — a hand-rolled byte-at-a-time loop, an unrecognised library — is
     * still a blind spot, the same way it always was; this closes the two idioms that account
     * for nearly every real one (a raw {@code readAllBytes()} and Spring's own converter).
     */
    public static void onRequestBodySource(Object stream) {
        AgentRuntime runtime = instance;
        ThreadState state = ThreadState.current();
        if (runtime == null || stream == null || !state.enter()) {
            return;
        }
        try {
            if (!runtime.governor.level().allowsDataflow()) {
                return;
            }
            RequestContext context = state.context();
            if (context == null || !context.isSampled()) {
                return;
            }
            dev.aegis.agent.taint.TaintedValue taint =
                    dev.aegis.agent.taint.TaintedValue.fullyTainted(
                                    1, dev.aegis.agent.taint.SourceKind.BODY, "request-body")
                            .reshaped(1);
            context.tracker().track(stream, taint);
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            state.exit();
        }
    }

    /** Mark a value returned by a source as attacker-controllable. */
    public static void onSource(
            String value, dev.aegis.agent.taint.SourceKind kind, String name) {
        AgentRuntime runtime = instance;
        ThreadState state = ThreadState.current();
        if (runtime == null || !state.enter()) {
            return;
        }
        if (runtime == null || !runtime.governor.level().allowsDataflow()) {
            return;
        }
        try {
            RequestContext context = state.context();
            if (context == null || !context.isSampled()) {
                return;
            }
            context.tracker().trackSource(value, kind, name);
            context.recordParameter(name, value);
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            state.exit();
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
        ThreadState state = ThreadState.current();
        if (runtime == null || !state.enter()) {
            return;
        }
        if (runtime == null || result == null || !runtime.governor.level().allowsDataflow()) {
            return;
        }
        try {
            RequestContext context = state.context();
            if (context == null || !context.isSampled()) {
                return;
            }
            TaintTracker tracker = context.tracker();
            if (tracker.isEmpty()) {
                return;
            }
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
            state.exit();
        }
    }

    // --- invokedynamic string concatenation ------------------------------------------------

    /** Placeholder in a {@code StringConcatFactory} recipe for a dynamic argument. */
    private static final char RECIPE_ARGUMENT = '\u0001';

    /** Placeholder for a constant supplied alongside the recipe. */
    private static final char RECIPE_CONSTANT = '\u0002';

    /** Refuse to rewrite absurdly wide call sites rather than pay for them on every execution. */
    private static final int MAX_CONCAT_ARGUMENTS = 128;

    private static final java.lang.invoke.MethodHandle CONCAT_TRACKER = findConcatTracker();

    private static java.lang.invoke.MethodHandle findConcatTracker() {
        try {
            return java.lang.invoke.MethodHandles.lookup()
                    .findStatic(
                            AgentRuntime.class,
                            "concatWithTracking",
                            java.lang.invoke.MethodType.methodType(
                                    Object.class,
                                    java.lang.invoke.MethodHandle.class,
                                    String.class,
                                    Object[].class,
                                    Object[].class));
        } catch (ReflectiveOperationException e) {
            return null;
        }
    }

    /**
     * Rewrite a string-concatenation call site so the agent sees the result.
     *
     * <p>Since Java 9, {@code "a" + b} does not compile to {@code StringBuilder}. It compiles
     * to an {@code invokedynamic} that asks {@link java.lang.invoke.StringConcatFactory} to
     * spin a bespoke method handle. An agent that instruments only {@code StringBuilder}
     * therefore misses the single most common way SQL injection is written in Java — and
     * misses it silently, which is far worse than missing it loudly.
     *
     * <p>The rewrite happens once, when the call site links, not on every concatenation. What
     * runs afterwards is the original handle plus one call into the tracker.
     *
     * @param recipe the layout string, or null for the constant-free {@code makeConcat} form
     * @param constants values the recipe interleaves between the dynamic arguments
     */
    public static java.lang.invoke.CallSite wrapConcat(
            java.lang.invoke.CallSite site, String owner, String recipe, Object[] constants) {
        ThreadState state = ThreadState.current();
        if (instance == null || site == null || CONCAT_TRACKER == null) {
            return site;
        }
        if (isPlatformClass(owner)) {
            // The JDK concatenates constantly — in logging, formatting, exception messages,
            // the class loader — and none of it is a place a customer's injection is written.
            // Wrapping those sites cost more overhead than every other hook combined, for no
            // detection whatsoever. Measured, not assumed: it was most of an 19% regression.
            return site;
        }
        if (!state.enter()) {
            // The agent's own code concatenates strings. Rewriting a call site while already
            // inside the agent risks recursion during linkage, and the sites we would lose are
            // ours, not the application's.
            return site;
        }
        try {
            java.lang.invoke.MethodHandle target = site.getTarget();
            java.lang.invoke.MethodType type = target.type();
            int arity = type.parameterCount();
            if (type.returnType() != String.class || arity == 0 || arity > MAX_CONCAT_ARGUMENTS) {
                return site;
            }

            // Generalize to all-Object so primitive arguments box cleanly on the way through
            // the spreader; asType puts the exact signature back at the end.
            java.lang.invoke.MethodHandle spread =
                    target.asType(type.generic()).asSpreader(Object[].class, arity);
            java.lang.invoke.MethodHandle bound =
                    java.lang.invoke.MethodHandles.insertArguments(
                            CONCAT_TRACKER,
                            0,
                            spread,
                            recipe == null ? defaultRecipe(arity) : recipe,
                            constants == null ? new Object[0] : constants);
            return new java.lang.invoke.ConstantCallSite(
                    bound.asCollector(Object[].class, arity).asType(type));
        } catch (Throwable t) {
            instance.hookFailed(t);
            // An un-rewritten call site is a coverage gap. A broken one is a broken application.
            return site;
        } finally {
            state.exit();
        }
    }

    private static String defaultRecipe(int arity) {
        return String.valueOf(RECIPE_ARGUMENT).repeat(arity);
    }

    /** Classes shipped with the platform, which never contain the customer's defects. */
    private static boolean isPlatformClass(String name) {
        if (name == null) {
            return false;
        }
        return name.startsWith("java.")
                || name.startsWith("javax.")
                || name.startsWith("jdk.")
                || name.startsWith("sun.")
                || name.startsWith("com.sun.")
                || name.startsWith("dev.aegis.");
    }

    /**
     * Runs in place of the original concatenation handle.
     *
     * <p>Called on the application's thread for every {@code +} it executes, so the fast path
     * matters: the original handle first, then one guarded call that returns almost immediately
     * when there is no request in flight.
     */
    public static Object concatWithTracking(
            java.lang.invoke.MethodHandle target,
            String recipe,
            Object[] constants,
            Object[] arguments)
            throws Throwable {
        // invokeExact, not invoke: the handle is generalized to (Object[])Object when the call
        // site is rewritten, so the descriptor matches exactly and the JVM skips the asType
        // adaptation it would otherwise insert on every single concatenation.
        Object result = (Object) target.invokeExact(arguments);
        if (result instanceof String text) {
            onIndyConcat(text, recipe, constants, arguments);
        }
        return result;
    }

    /**
     * Reconstruct where each argument landed in the result and propagate its taint.
     *
     * <p>Offsets come from the recipe rather than from searching the result for each argument.
     * Searching would be both slower and wrong: a value appearing twice would attribute the
     * taint to whichever copy came first.
     */
    private static void onIndyConcat(
            String result, String recipe, Object[] constants, Object[] arguments) {
        AgentRuntime runtime = instance;
        ThreadState state = ThreadState.current();
        if (runtime == null || !state.enter()) {
            return;
        }
        try {
            if (!runtime.governor.level().allowsDataflow()) {
                return;
            }
            RequestContext context = state.context();
            if (context == null || !context.isSampled()) {
                return;
            }
            TaintTracker tracker = context.tracker();
            if (tracker.isEmpty()) {
                return;
            }

            boolean anyTainted = false;
            for (Object argument : arguments) {
                if (tracker.taintOf(argument).isTainted()) {
                    anyTainted = true;
                    break;
                }
            }
            if (!anyTainted) {
                return;
            }

            TaintedValue accumulated = TaintedValue.empty();
            int offset = 0;
            int argumentIndex = 0;
            int constantIndex = 0;

            for (int position = 0; position < recipe.length(); position++) {
                char marker = recipe.charAt(position);
                if (marker == RECIPE_ARGUMENT) {
                    if (argumentIndex >= arguments.length) {
                        return;
                    }
                    Object argument = arguments[argumentIndex++];
                    TaintedValue taint = tracker.taintOf(argument);
                    accumulated = TaintedValue.concat(accumulated, offset, taint);
                    offset += String.valueOf(argument).length();
                } else if (marker == RECIPE_CONSTANT) {
                    if (constantIndex >= constants.length) {
                        return;
                    }
                    offset += String.valueOf(constants[constantIndex++]).length();
                } else {
                    offset++;
                }
            }

            // If the reconstruction disagrees with reality the offsets are meaningless, and a
            // finding pointing at the wrong characters is worse than no finding at all.
            if (offset != result.length()) {
                return;
            }
            tracker.track(result, accumulated);
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            state.exit();
        }
    }

    /**
     * {@code StringBuilder.append(x)} — the builder itself carries the accumulated taint.
     *
     * <p>Taint is keyed on the builder object, not on any intermediate string, so a query
     * assembled across a dozen appends and materialized once by {@code toString()} still
     * arrives at the sink with correct offsets.
     *
     * @param lengthBefore the builder's length prior to this append, captured on entry
     */
    public static void onBuilderAppend(Object builder, int lengthBefore, Object appended) {
        AgentRuntime runtime = instance;
        ThreadState state = ThreadState.current();
        if (runtime == null || !state.enter()) {
            return;
        }
        if (runtime == null || builder == null || !runtime.governor.level().allowsDataflow()) {
            return;
        }
        try {
            RequestContext context = state.context();
            if (context == null || !context.isSampled()) {
                return;
            }
            TaintTracker tracker = context.tracker();
            if (tracker.isEmpty()) {
                return;
            }
            TaintedValue appendedTaint = tracker.taintOf(appended);
            TaintedValue builderTaint = tracker.taintOf(builder);
            if (!appendedTaint.isTainted() && !builderTaint.isTainted()) {
                return;
            }
            tracker.track(builder, TaintedValue.concat(builderTaint, lengthBefore, appendedTaint));
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            state.exit();
        }
    }

    /**
     * {@code StringBuilder.replace(start, end, value)} — remove old ranges and insert the
     * replacement's ranges at their new offsets.
     */
    public static void onBuilderReplace(
            Object builder,
            int lengthBefore,
            int from,
            int to,
            Object replacement,
            int replacementLength) {
        AgentRuntime runtime = instance;
        ThreadState state = ThreadState.current();
        if (runtime == null || builder == null || !state.enter()) {
            return;
        }
        try {
            if (!runtime.governor.level().allowsDataflow()) {
                return;
            }
            RequestContext context = state.context();
            if (context == null || !context.isSampled()) {
                return;
            }
            TaintTracker tracker = context.tracker();
            if (tracker.isEmpty()) {
                return;
            }
            TaintedValue builderTaint = tracker.taintOf(builder);
            TaintedValue replacementTaint = tracker.taintOf(replacement);
            if (!builderTaint.isTainted() && !replacementTaint.isTainted()) {
                return;
            }

            // AbstractStringBuilder truncates end to its current length. The advice runs only
            // after a successful call, so start and the effective end are now known-valid.
            int effectiveTo = Math.min(to, lengthBefore);
            tracker.track(
                    builder,
                    builderTaint.replace(
                            from, effectiveTo, replacementTaint, replacementLength));
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            state.exit();
        }
    }

    /** {@code StringBuilder.reverse()} — mirror every tracked range across the final length. */
    public static void onBuilderReverse(Object builder, int length) {
        AgentRuntime runtime = instance;
        ThreadState state = ThreadState.current();
        if (runtime == null || builder == null || !state.enter()) {
            return;
        }
        try {
            if (!runtime.governor.level().allowsDataflow()) {
                return;
            }
            RequestContext context = state.context();
            if (context == null || !context.isSampled()) {
                return;
            }
            TaintTracker tracker = context.tracker();
            if (tracker.isEmpty()) {
                return;
            }
            TaintedValue builderTaint = tracker.taintOf(builder);
            if (builderTaint.isTainted()) {
                tracker.track(builder, builderTaint.reversed(length));
            }
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            state.exit();
        }
    }

    /**
     * {@code String.format(...)} and {@code String.formatted(...)} reshape tainted arguments
     * into one result whose exact offsets depend on the format directives.
     */
    public static void onStringFormat(String result, Object format, Object[] arguments) {
        AgentRuntime runtime = instance;
        ThreadState state = ThreadState.current();
        if (runtime == null || result == null || result.isEmpty() || !state.enter()) {
            return;
        }
        try {
            if (!runtime.governor.level().allowsDataflow()) {
                return;
            }
            RequestContext context = state.context();
            if (context == null || !context.isSampled()) {
                return;
            }
            TaintTracker tracker = context.tracker();
            if (tracker.isEmpty()) {
                return;
            }

            TaintedValue combined = tracker.taintOf(format);
            if (arguments != null) {
                for (Object argument : arguments) {
                    // Offsets are deliberately artificial here and discarded by reshaped().
                    // Using String.valueOf(argument) to calculate real widths would invoke
                    // application toString methods twice and could change application behavior.
                    combined = TaintedValue.concat(combined, 0, tracker.taintOf(argument));
                }
            }
            if (combined.isTainted()) {
                tracker.track(result, combined.reshaped(result.length()));
            }
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            state.exit();
        }
    }

    /** Decode the two static {@code String.format} overload shapes without library dependencies. */
    public static void onStaticStringFormat(String result, Object[] invocationArguments) {
        if (invocationArguments == null || invocationArguments.length < 2) {
            return;
        }
        int formatIndex = invocationArguments[0] instanceof String ? 0 : 1;
        if (formatIndex >= invocationArguments.length
                || !(invocationArguments[formatIndex] instanceof String format)) {
            return;
        }
        int argumentsIndex = formatIndex + 1;
        Object[] arguments =
                argumentsIndex < invocationArguments.length
                                && invocationArguments[argumentsIndex] instanceof Object[] values
                        ? values
                        : null;
        onStringFormat(result, format, arguments);
    }

    /**
     * Bind the current request context to a task that is about to run on another thread.
     *
     * <p>Returns the original task unchanged when there is nothing to carry, so the common
     * case adds no wrapper and no allocation to the application's executor.
     */
    public static Runnable wrapForHandoff(Runnable task) {
        AgentRuntime runtime = instance;
        ThreadState state = ThreadState.current();
        if (runtime == null || task == null) {
            return task;
        }
        if (!state.enter()) {
            return task;
        }
        try {
            RequestContext context = state.context();
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
            state.exit();
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
        ThreadState state = ThreadState.current();
        if (runtime == null || task == null) {
            return task;
        }
        if (!state.enter()) {
            return task;
        }
        try {
            RequestContext context = state.context();
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
            state.exit();
        }
    }

    /**
     * A transform that rewrites the value wholesale — {@code URLDecoder.decode} above all.
     *
     * <p>Almost every handler that reads a header or a cookie decodes it before doing anything
     * else, so a propagator that stops here loses the finding on the majority of real code
     * paths. Measured against the OWASP Benchmark, this single gap appeared in 234 of the 526
     * defects the agent missed.
     */
    public static void onReshapingTransform(String result, Object source) {
        AgentRuntime runtime = instance;
        ThreadState state = ThreadState.current();
        if (runtime == null || result == null || !state.enter()) {
            return;
        }
        try {
            RequestContext context = state.context();
            if (context == null || !context.isSampled()) {
                return;
            }
            TaintTracker tracker = context.tracker();
            if (tracker.isEmpty()) {
                return;
            }
            TaintedValue taint = tracker.taintOf(source);
            if (taint.isTainted()) {
                tracker.track(result, taint.reshaped(result.length()));
            }
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            state.exit();
        }
    }

    /**
     * {@code String.split(regex)} — one tainted value becomes several.
     *
     * <p>Each piece is reshaped rather than clipped. The split removes the delimiters, so no
     * element keeps the offsets it had in the original, and carrying them over would point a
     * developer at the wrong characters. Marking each piece wholly derived is the honest
     * description: the agent knows where the value came from and no longer knows the mapping.
     */
    public static void onSplit(Object[] pieces, Object source) {
        AgentRuntime runtime = instance;
        ThreadState state = ThreadState.current();
        if (runtime == null || pieces == null || !state.enter()) {
            return;
        }
        try {
            RequestContext context = state.context();
            if (context == null || !context.isSampled()) {
                return;
            }
            TaintTracker tracker = context.tracker();
            if (tracker.isEmpty()) {
                return;
            }
            TaintedValue taint = tracker.taintOf(source);
            if (!taint.isTainted()) {
                return;
            }
            for (Object piece : pieces) {
                if (piece instanceof String text && !text.isEmpty()) {
                    tracker.track(text, taint.reshaped(text.length()));
                }
            }
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            state.exit();
        }
    }

    /**
     * {@code ServletRequest.getHeaders(name)} — an enumeration whose elements are attacker data.
     *
     * <p>The enumeration cannot be read here: consuming it would hand the application an empty
     * one. It is wrapped instead, so each element is tainted at the moment the application takes
     * it. Returning the original unchanged on any failure keeps the application's contract
     * exactly as it was.
     */
    public static java.util.Enumeration<?> onHeaderEnumeration(
            java.util.Enumeration<?> values, String name) {
        AgentRuntime runtime = instance;
        ThreadState state = ThreadState.current();
        if (runtime == null || values == null || !state.enter()) {
            return values;
        }
        try {
            if (!runtime.governor.level().allowsDataflow()) {
                return values;
            }
            RequestContext context = state.context();
            if (context == null || !context.isSampled()) {
                return values;
            }
            return new TaintingEnumeration(values, name);
        } catch (Throwable t) {
            runtime.hookFailed(t);
            return values;
        } finally {
            state.exit();
        }
    }

    /** {@code HttpServletRequest.getHeaderNames()} — each returned name is attacker-controlled. */
    public static java.util.Enumeration<?> onHeaderNameEnumeration(
            java.util.Enumeration<?> names) {
        return onHeaderEnumeration(names, null);
    }

    /** Taints each element as the application takes it, and is otherwise transparent. */
    private static final class TaintingEnumeration implements java.util.Enumeration<Object> {

        private final java.util.Enumeration<?> delegate;
        private final String name;

        TaintingEnumeration(java.util.Enumeration<?> delegate, String name) {
            this.delegate = delegate;
            this.name = name;
        }

        @Override
        public boolean hasMoreElements() {
            return delegate.hasMoreElements();
        }

        @Override
        public Object nextElement() {
            Object value = delegate.nextElement();
            if (value instanceof String text) {
                onSource(
                        text,
                        dev.aegis.agent.taint.SourceKind.HEADER,
                        name == null ? text : name);
            }
            return value;
        }
    }

    /**
     * {@code ProcessBuilder.start()} — the execution point, whatever built the command.
     *
     * <p>Hooked here rather than on {@code command(...)} because a builder can be filled by its
     * constructor, by {@code command(List)}, or by mutating the list it returns. {@code start}
     * is the one place all of those meet.
     */
    public static void onProcessStart(java.lang.ProcessBuilder builder) {
        if (instance == null || builder == null) {
            return;
        }
        try {
            for (String argument : builder.command()) {
                // Deliberately outside the guard: onSink takes it, and it captures the stack,
                // which has to show the application frame that started the process.
                onSink(argument, RuleClass.COMMAND_INJECTION, "java.lang.ProcessBuilder#start()");
            }
        } catch (Throwable t) {
            instance.hookFailed(t);
        }
    }

    /**
     * {@code PrintWriter.format/printf} — a format string written to the response body.
     *
     * <p>Every argument is checked, not just the format string: a tainted value substituted into
     * the page is reflected XSS just as surely as a tainted template is.
     */
    public static void onResponseFormat(Object target, Object[] arguments) {
        AgentRuntime runtime = instance;
        ThreadState state = ThreadState.current();
        if (runtime == null || arguments == null || !state.enter()) {
            return;
        }
        boolean isResponse;
        try {
            RequestContext context = state.context();
            isResponse = context != null && context.isResponseChannel(target);
        } catch (Throwable t) {
            runtime.hookFailed(t);
            return;
        } finally {
            state.exit();
        }
        if (!isResponse) {
            return;
        }
        for (Object argument : arguments) {
            if (argument instanceof String) {
                onSink(
                        argument,
                        RuleClass.REFLECTED_XSS,
                        "java.io.PrintWriter#format(String,Object...)");
            } else if (argument instanceof Object[] nested) {
                for (Object element : nested) {
                    onSink(
                            element,
                            RuleClass.REFLECTED_XSS,
                            "java.io.PrintWriter#format(String,Object...)");
                }
            }
        }
    }

    /** A length-preserving transform such as {@code toUpperCase} or {@code intern}. */
    public static void onPreservingTransform(String result, Object source) {
        AgentRuntime runtime = instance;
        ThreadState state = ThreadState.current();
        if (runtime == null || !state.enter()) {
            return;
        }
        if (runtime == null || result == null) {
            return;
        }
        try {
            RequestContext context = state.context();
            if (context == null || !context.isSampled()) {
                return;
            }
            TaintTracker tracker = context.tracker();
            if (tracker.isEmpty()) {
                return;
            }
            TaintedValue taint = tracker.taintOf(source);
            if (taint.isTainted()) {
                tracker.track(result, taint.preservingTransform());
            }
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            state.exit();
        }
    }

    /** {@code source.substring(from, to)}. */
    public static void onSubstring(String result, Object source, int from, int to) {
        AgentRuntime runtime = instance;
        ThreadState state = ThreadState.current();
        if (runtime == null || !state.enter()) {
            return;
        }
        if (runtime == null || result == null) {
            return;
        }
        try {
            RequestContext context = state.context();
            if (context == null || !context.isSampled()) {
                return;
            }
            TaintTracker tracker = context.tracker();
            if (tracker.isEmpty()) {
                return;
            }
            TaintedValue taint = tracker.taintOf(source);
            if (taint.isTainted()) {
                tracker.track(result, taint.substring(from, to));
            }
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            state.exit();
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
        ThreadState state = ThreadState.current();
        if (runtime == null || !state.enter()) {
            return;
        }
        if (runtime == null || result == null) {
            return;
        }
        try {
            RequestContext context = state.context();
            if (context == null) {
                return;
            }
            TaintTracker tracker = context.tracker();
            if (tracker.isEmpty()) {
                return;
            }
            TaintedValue taint = tracker.taintOf(source);
            if (taint.isTainted()) {
                tracker.track(result, taint.sanitizedFor(rule));
            }
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            state.exit();
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
        ThreadState state = ThreadState.current();
        if (runtime == null || !(argument instanceof String value)) {
            return null;
        }
        if (!state.enter()) {
            return null;
        }
        if (!runtime.governor.level().allowsDataflow()) {
            return null;
        }
        try {
            RequestContext context = state.context();
            if (context == null || !context.isSampled()) {
                return null;
            }
            runtime.sinksEvaluated.incrementAndGet();
            if (context.tracker().isEmpty()) {
                return null;
            }

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
            // Reported once per defect per request. The finding is still returned either way,
            // because blocking mode has to act on every occurrence, not just the first.
            if (finding != null
                    && context.firstReport(
                            finding.rule().key() + "|" + finding.stackFingerprint())) {
                runtime.findingsReported.incrementAndGet();
                runtime.reporter.report(finding, context);
            }
            return finding;
        } catch (Throwable t) {
            runtime.hookFailed(t);
            return null;
        } finally {
            state.exit();
        }
    }

    /**
     * A sink whose dangerous argument is not a string.
     *
     * <p>Deserialization is the case that needs this: what reaches
     * {@code ObjectInputStream.readObject} is a stream, and the taint arrived as bytes. The
     * evidence is therefore the provenance rather than the value — reproducing an attacker's
     * serialized payload in a finding would be handing it back out in a report.
     */
    public static Finding onObjectSink(Object argument, RuleClass rule, String sinkSignature) {
        AgentRuntime runtime = instance;
        ThreadState state = ThreadState.current();
        if (runtime == null || argument == null || !state.enter()) {
            return null;
        }
        try {
            if (!runtime.governor.level().allowsDataflow()) {
                return null;
            }
            RequestContext context = state.context();
            if (context == null || !context.isSampled() || context.tracker().isEmpty()) {
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
                            "<" + argument.getClass().getSimpleName() + ">",
                            rule,
                            sinkSignature,
                            new Throwable().getStackTrace(),
                            false);
            if (finding != null
                    && context.firstReport(
                            finding.rule().key() + "|" + finding.stackFingerprint())) {
                runtime.findingsReported.incrementAndGet();
                runtime.reporter.report(finding, context);
            }
            return finding;
        } catch (Throwable t) {
            runtime.hookFailed(t);
            return null;
        } finally {
            state.exit();
        }
    }

    /**
     * Carry taint from a value onto a derived object — {@code String.getBytes()}, a stream
     * wrapping a buffer, a reader wrapping a stream.
     *
     * <p>Without this the taint table only ever holds strings, and every dataflow that leaves
     * the character world — which is every deserialization attack — becomes invisible.
     */
    public static void onDerivedObject(Object derived, Object source) {
        AgentRuntime runtime = instance;
        ThreadState state = ThreadState.current();
        if (runtime == null || derived == null || !state.enter()) {
            return;
        }
        try {
            RequestContext context = state.context();
            if (context == null || !context.isSampled()) {
                return;
            }
            TaintTracker tracker = context.tracker();
            if (tracker.isEmpty()) {
                return;
            }
            TaintedValue taint = tracker.taintOf(source);
            if (taint.isTainted()) {
                tracker.track(derived, taint);
            }
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            state.exit();
        }
    }

    /**
     * {@code ServletResponse.getWriter()} — remember where the response body goes.
     *
     * <p>Reflected XSS is a sink on the response, but the write happens on a {@code Writer} that
     * has no idea it belongs to one. Instrumenting every writer and reporting on all of them
     * would flag {@code System.out}; remembering the specific object the response handed out
     * makes the check exact and costs one identity lookup.
     */
    public static void onResponseChannel(Object channel) {
        AgentRuntime runtime = instance;
        ThreadState state = ThreadState.current();
        if (runtime == null || channel == null || !state.enter()) {
            return;
        }
        try {
            RequestContext context = state.context();
            if (context != null) {
                context.registerResponseChannel(channel);
            }
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            state.exit();
        }
    }

    /** A write to something. Reports only when the target is this request's response body. */
    public static void onResponseWrite(Object target, Object value) {
        AgentRuntime runtime = instance;
        ThreadState state = ThreadState.current();
        if (runtime == null || !(value instanceof String) || !state.enter()) {
            return;
        }
        boolean isResponse;
        try {
            RequestContext context = state.context();
            isResponse = context != null && context.isResponseChannel(target);
        } catch (Throwable t) {
            runtime.hookFailed(t);
            return;
        } finally {
            state.exit();
        }
        if (isResponse) {
            // Outside the guard: onSink takes it again, and it also captures the stack, which
            // must show the application frame that wrote — not this method.
            onSink(value, RuleClass.REFLECTED_XSS, "jakarta.servlet.ServletResponse#getWriter");
        }
    }

    /**
     * A URL-context encoder ran — {@code URLEncoder.encode} and friends.
     *
     * <p>Percent-encoding makes a value safe to place in a URL or a header. It does nothing
     * whatsoever to make it safe in HTML or in SQL, so exactly three rule classes are cleared
     * and the rest are deliberately left alone (ADR-0007).
     */
    public static void onUrlEncoded(String result, Object source) {
        sanitize(result, source, RuleClass.OPEN_REDIRECT, RuleClass.HEADER_INJECTION, RuleClass.SSRF);
    }

    /** An HTML or XML escaper ran. Clears reflected XSS, and nothing else. */
    public static void onHtmlEscaped(String result, Object source) {
        sanitize(result, source, RuleClass.REFLECTED_XSS);
    }

    /** An LDAP or XPath encoder ran. */
    public static void onQueryEncoded(String result, Object source) {
        sanitize(result, source, RuleClass.LDAP_INJECTION, RuleClass.XPATH_INJECTION);
    }

    private static void sanitize(String result, Object source, RuleClass... rules) {
        AgentRuntime runtime = instance;
        ThreadState state = ThreadState.current();
        if (runtime == null || result == null || !state.enter()) {
            return;
        }
        try {
            RequestContext context = state.context();
            if (context == null) {
                return;
            }
            TaintTracker tracker = context.tracker();
            if (tracker.isEmpty()) {
                return;
            }
            TaintedValue taint = tracker.taintOf(source);
            if (!taint.isTainted()) {
                return;
            }
            for (RuleClass rule : rules) {
                taint = taint.sanitizedFor(rule);
            }
            tracker.track(result, taint);
        } catch (Throwable t) {
            runtime.hookFailed(t);
        } finally {
            state.exit();
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
