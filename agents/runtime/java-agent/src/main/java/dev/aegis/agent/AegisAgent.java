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
        Method bootstrap =
                runtimeClass.getMethod(
                        "bootstrap",
                        String[].class,
                        String.class,
                        int.class,
                        String[].class,
                        int.class,
                        double.class,
                        String.class,
                        String.class,
                        long.class);
        bootstrap.invoke(
                null,
                config.redactKeys().toArray(new String[0]),
                config.captureMode().name(),
                config.maxValueLength(),
                config.applicationPackages().toArray(new String[0]),
                config.bufferCapacity(),
                config.cpuBudgetPct(),
                config.endpoint(),
                config.apiKey(),
                1_000L);
    }

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

        builder.installOn(instrumentation);
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
