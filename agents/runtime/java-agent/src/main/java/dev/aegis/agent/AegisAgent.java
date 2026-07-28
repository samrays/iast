package dev.aegis.agent;

import dev.aegis.agent.boot.BootstrapInjector;
import dev.aegis.agent.instrument.Advices;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.utility.JavaModule;

/**
 * Agent entry point.
 *
 * <p>Loaded through {@code -javaagent:aegis-agent.jar} before the application's {@code main},
 * or attached at runtime via {@code agentmain}.
 *
 * <p>Two properties dominate this class. First, <b>bootstrap must never abort startup</b>:
 * every failure path logs at most one line and lets the application come up uninstrumented,
 * because a security tool that prevents a service from booting is worse than no security
 * tool. Second, <b>instrumentation is opt-in per type</b> — matching broadly and filtering
 * later would mean walking every class the application loads, which is where agents acquire
 * their reputation for slow startup.
 */
public final class AegisAgent {

    private static volatile boolean installed;

    private AegisAgent() {}

    /** Invoked by the JVM before {@code main}. */
    public static void premain(String agentArgs, Instrumentation instrumentation) {
        install(agentArgs, instrumentation, "premain");
    }

    /** Invoked on dynamic attach. */
    public static void agentmain(String agentArgs, Instrumentation instrumentation) {
        install(agentArgs, instrumentation, "attach");
    }

    static synchronized void install(
            String agentArgs, Instrumentation instrumentation, String via) {
        if (installed) {
            return;
        }
        try {
            // FIRST, before any reference to AgentRuntime or AgentConfig. Once the system
            // loader has defined either of those, adding a second copy on bootstrap makes
            // the JVM see two distinct types and refuse to link (see BootstrapInjector).
            boolean coreInstrumentationAvailable = BootstrapInjector.inject(instrumentation);

            AgentConfig config = AgentConfig.fromAgentArgs(agentArgs);
            bootstrapRuntime(config);
            installTransformers(instrumentation);
            installed = true;
            System.out.println(
                    "[aegis] agent installed via "
                            + via
                            + " for "
                            + config.applicationName()
                            + " ("
                            + config.environment()
                            + "), budget "
                            + config.cpuBudgetPct()
                            + "%"
                            + (coreInstrumentationAvailable
                                    ? ""
                                    : " [core instrumentation unavailable]"));
        } catch (Throwable t) {
            // The application still boots. It is simply not instrumented, and the operator
            // sees exactly one line saying so — but that line must name the *cause*, not the
            // reflection wrapper, or diagnosing a failed install means guessing.
            Throwable cause = t;
            while (cause.getCause() != null && cause != cause.getCause()) {
                cause = cause.getCause();
            }
            System.err.println(
                    "[aegis] agent failed to install; application unaffected: " + cause);
            if (Boolean.getBoolean("aegis.debug")) {
                cause.printStackTrace();
            }
        }
    }

    /**
     * Start the runtime through reflection.
     *
     * <p>This class is on the system class path and the runtime is on the bootstrap path. A
     * direct call would make the verifier resolve {@code AgentRuntime} here, defining a
     * second copy on the system loader — and then the inlined advice (bootstrap) would set
     * its static instance on one copy while this code read the other, so every hook would
     * silently find a null runtime and report nothing. Reflection keeps exactly one copy.
     */
    static void bootstrapRuntime(AgentConfig config) throws ReflectiveOperationException {
        Class<?> runtimeClass = Class.forName("dev.aegis.agent.AgentRuntime", true, null);
        Method bootstrap = runtimeClass.getMethod("bootstrap", java.util.Map.class);
        bootstrap.invoke(null, config.toMap());
    }

    /**
     * Types whose {@code execute}/{@code submit} carry work to another thread.
     *
     * <p>Named explicitly, because matching every implementation of {@code Executor} means
     * resolving the supertype hierarchy of every class the application loads — which is how an
     * agent turns a 4-second startup into a 40-second one. These four cover the JDK pools, and
     * {@code ThreadPoolExecutor} covers everything built on it, including
     * {@code Executors.newFixedThreadPool} and Spring's task executors.
     */
    private static final String[] EXECUTOR_TYPES = {
        "java.util.concurrent.ThreadPoolExecutor",
        "java.util.concurrent.ForkJoinPool",
        "java.util.concurrent.ScheduledThreadPoolExecutor",
        "java.util.concurrent.AbstractExecutorService",
    };

    static void installTransformers(Instrumentation instrumentation) {
        AgentBuilder builder =
                new AgentBuilder.Default()
                        .disableClassFormatChanges()
                        .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
                        .with(new FailSafeListener())
                        // Never instrument our own classes: advice calling into instrumented
                        // agent code is an infinite recursion inside the customer's process.
                        .ignore(ElementMatchers.nameStartsWith("dev.aegis."))
                        .ignore(ElementMatchers.nameStartsWith("net.bytebuddy."))
                        .ignore(ElementMatchers.nameStartsWith("jdk.internal."));

        // --- propagators ----------------------------------------------------------------
        builder =
                builder.type(ElementMatchers.named("java.lang.String"))
                        .transform(
                                (b, type, loader, module, pd) ->
                                        b.visit(
                                                        net.bytebuddy.asm.Advice.to(
                                                                        Advices.StringConcat.class)
                                                                .on(
                                                                        ElementMatchers.named("concat")
                                                                                .and(
                                                                                        ElementMatchers
                                                                                                .takesArguments(
                                                                                                        String
                                                                                                                .class))))
                                                .visit(
                                                        net.bytebuddy.asm.Advice.to(
                                                                        Advices.Substring.class)
                                                                .on(
                                                                        ElementMatchers.named(
                                                                                "substring")))
                                                .visit(
                                                        net.bytebuddy.asm.Advice.to(
                                                                        Advices.Preserving.class)
                                                                .on(
                                                                        ElementMatchers.namedOneOf(
                                                                                "toLowerCase",
                                                                                "toUpperCase",
                                                                                "trim",
                                                                                "strip",
                                                                                "intern"))));

        builder =
                builder.type(
                                ElementMatchers.namedOneOf(
                                        "java.lang.StringBuilder", "java.lang.StringBuffer"))
                        .transform(
                                (b, type, loader, module, pd) ->
                                        b.visit(
                                                        net.bytebuddy.asm.Advice.to(
                                                                        Advices.BuilderAppend.class)
                                                                .on(
                                                                        ElementMatchers.named("append")
                                                                                .and(
                                                                                        ElementMatchers
                                                                                                .takesArguments(
                                                                                                        1))))
                                                .visit(
                                                        net.bytebuddy.asm.Advice.to(
                                                                        Advices.BuilderToString.class)
                                                                .on(
                                                                        ElementMatchers.named(
                                                                                        "toString")
                                                                                .and(
                                                                                        ElementMatchers
                                                                                                .takesNoArguments()))));

        // --- sinks -----------------------------------------------------------------------
        builder =
                builder.type(
                                ElementMatchers.isSubTypeOf(java.sql.Statement.class)
                                        .and(
                                                ElementMatchers.not(
                                                        ElementMatchers.isSubTypeOf(
                                                                java.sql.PreparedStatement.class))))
                        .transform(
                                (b, type, loader, module, pd) ->
                                        b.visit(
                                                net.bytebuddy.asm.Advice.to(
                                                                Advices.JdbcStatement.class)
                                                        .on(
                                                                ElementMatchers.nameStartsWith(
                                                                                "execute")
                                                                        .and(
                                                                                ElementMatchers
                                                                                        .takesArgument(
                                                                                                0,
                                                                                                String
                                                                                                        .class)))));

        builder =
                builder.type(ElementMatchers.named("java.lang.Runtime"))
                        .transform(
                                (b, type, loader, module, pd) ->
                                        b.visit(
                                                net.bytebuddy.asm.Advice.to(Advices.CommandExec.class)
                                                        .on(
                                                                ElementMatchers.named("exec")
                                                                        .and(
                                                                                ElementMatchers
                                                                                        .takesArgument(
                                                                                                0,
                                                                                                String
                                                                                                        .class)))));

        // The `+` operator. Instrumenting the factory that links the call site costs nothing
        // per concatenation — the rewrite happens once, when the site links — and without it
        // the agent misses every injection written the way most Java is written.
        builder =
                builder.type(ElementMatchers.named("java.lang.invoke.StringConcatFactory"))
                        .transform(
                                (b, type, loader, module, pd) ->
                                        b.visit(
                                                        net.bytebuddy.asm.Advice.to(
                                                                        Advices
                                                                                .ConcatFactoryWithConstants
                                                                                .class)
                                                                .on(
                                                                        ElementMatchers.named(
                                                                                "makeConcatWithConstants")))
                                                .visit(
                                                        net.bytebuddy.asm.Advice.to(
                                                                        Advices.ConcatFactory.class)
                                                                .on(
                                                                        ElementMatchers.named(
                                                                                "makeConcat"))));

        // Path traversal. The constructor is the sink rather than the later read: by the time
        // anything is opened the path has usually been passed around, and the stack trace at
        // construction is the one that names the line a developer has to change.
        builder =
                builder.type(ElementMatchers.named("java.io.File"))
                        .transform(
                                (b, type, loader, module, pd) ->
                                        b.visit(
                                                net.bytebuddy.asm.Advice.to(Advices.FileAccess.class)
                                                        .on(
                                                                ElementMatchers.isConstructor()
                                                                        .and(
                                                                                ElementMatchers
                                                                                        .takesArgument(
                                                                                                0,
                                                                                                String
                                                                                                        .class)))));

        builder = installHttpTransformers(builder);
        builder = installAsyncTransformers(builder);

        builder.installOn(instrumentation);
    }

    /**
     * HTTP entry point and sources, for both servlet API generations.
     *
     * <p>Nothing here names a servlet type at compile time. The agent must run against
     * {@code jakarta.servlet} and {@code javax.servlet} alike, and — more fundamentally — the
     * advice targets are on the application's class loader while the runtime it calls is on
     * bootstrap, so matching is by name and reading is by reflection.
     */
    private static AgentBuilder installHttpTransformers(AgentBuilder builder) {
        // The abstract base class every servlet extends. Matching it by exact name costs
        // nothing at class-load time, unlike walking the hierarchy of every loaded class to
        // ask whether it implements Servlet.
        builder =
                builder.type(
                                ElementMatchers.namedOneOf(
                                        "jakarta.servlet.http.HttpServlet",
                                        "javax.servlet.http.HttpServlet"))
                        .transform(
                                (b, type, loader, module, pd) ->
                                        b.visit(
                                                net.bytebuddy.asm.Advice.to(Advices.HttpEntry.class)
                                                        .on(
                                                                ElementMatchers.named("service")
                                                                        .and(
                                                                                ElementMatchers
                                                                                        .takesArguments(
                                                                                                2)))));

        // Request implementations, on the other hand, have no single base type: Tomcat's
        // RequestFacade, Jetty's Request and every framework wrapper are unrelated classes
        // sharing only the interface. The name pre-filter keeps the expensive hierarchy walk
        // off the 99% of classes that could not possibly be one.
        net.bytebuddy.matcher.ElementMatcher.Junction<TypeDescription> servletRequest =
                ElementMatchers.<TypeDescription>nameContains("Request")
                        .and(
                                ElementMatchers.hasSuperType(
                                        ElementMatchers.namedOneOf(
                                                "jakarta.servlet.ServletRequest",
                                                "javax.servlet.ServletRequest")));

        builder =
                builder.type(servletRequest)
                        .transform(
                                (b, type, loader, module, pd) ->
                                        b.visit(
                                                        net.bytebuddy.asm.Advice.to(
                                                                        Advices.HttpStringSource
                                                                                .class)
                                                                .on(
                                                                        ElementMatchers.namedOneOf(
                                                                                        "getParameter",
                                                                                        "getParameterValues",
                                                                                        "getHeader",
                                                                                        "getQueryString",
                                                                                        "getPathInfo",
                                                                                        "getPathTranslated",
                                                                                        "getRequestURI")
                                                                                .and(
                                                                                        ElementMatchers
                                                                                                .isPublic())))
                                                .visit(
                                                        net.bytebuddy.asm.Advice.to(
                                                                        Advices.RequestBodyAccess
                                                                                .class)
                                                                .on(
                                                                        ElementMatchers.namedOneOf(
                                                                                        "getInputStream",
                                                                                        "getReader")
                                                                                .and(
                                                                                        ElementMatchers
                                                                                                .isPublic()))));

        builder =
                builder.type(
                                ElementMatchers.namedOneOf(
                                        "jakarta.servlet.http.Cookie", "javax.servlet.http.Cookie"))
                        .transform(
                                (b, type, loader, module, pd) ->
                                        b.visit(
                                                net.bytebuddy.asm.Advice.to(
                                                                Advices.CookieValue.class)
                                                        .on(
                                                                ElementMatchers.named("getValue")
                                                                        .and(
                                                                                ElementMatchers
                                                                                        .takesNoArguments()))));
        return builder;
    }

    /**
     * Carry the request context across thread hand-offs.
     *
     * <p>Without this, taint dies at the first {@code executor.submit(...)} and the agent
     * silently under-reports on exactly the asynchronous codebases that most need checking —
     * the worst kind of failure for a security tool, because the output still looks clean.
     */
    private static AgentBuilder installAsyncTransformers(AgentBuilder builder) {
        return builder.type(ElementMatchers.namedOneOf(EXECUTOR_TYPES))
                .transform(
                        (b, type, loader, module, pd) ->
                                b.visit(
                                                net.bytebuddy.asm.Advice.to(
                                                                Advices.ExecutorSubmit.class)
                                                        .on(
                                                                ElementMatchers.namedOneOf(
                                                                                "execute", "submit")
                                                                        .and(
                                                                                ElementMatchers
                                                                                        .takesArgument(
                                                                                                0,
                                                                                                Runnable
                                                                                                        .class))))
                                        .visit(
                                                net.bytebuddy.asm.Advice.to(
                                                                Advices.CallableSubmit.class)
                                                        .on(
                                                                ElementMatchers.named("submit")
                                                                        .and(
                                                                                ElementMatchers
                                                                                        .takesArgument(
                                                                                                0,
                                                                                                java.util
                                                                                                        .concurrent
                                                                                                        .Callable
                                                                                                        .class)))));
    }

    /**
     * Swallows transformation failures.
     *
     * <p>A class the agent cannot transform is a coverage gap, never a reason to fail. Some
     * classes legitimately resist instrumentation — sealed JDK internals, classes already
     * transformed by another agent — and the correct response is to carry on without them and
     * report the gap.
     */
    static final class FailSafeListener extends AgentBuilder.Listener.Adapter {
        @Override
        public void onError(
                String typeName,
                ClassLoader classLoader,
                JavaModule module,
                boolean loaded,
                Throwable throwable) {
            if (Boolean.getBoolean("aegis.debug")) {
                System.err.println("[aegis] could not instrument " + typeName + ": " + throwable);
            }
        }

        @Override
        public void onTransformation(
                TypeDescription typeDescription,
                ClassLoader classLoader,
                JavaModule module,
                boolean loaded,
                net.bytebuddy.dynamic.DynamicType dynamicType) {
            if (Boolean.getBoolean("aegis.debug")) {
                System.err.println("[aegis] instrumented " + typeDescription.getName());
            }
        }
    }
}
