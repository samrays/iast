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
     * JDK types that must exist before the retransformation sweep runs.
     *
     * <p>{@code java.io.ObjectInputStream} is never offered to the class-file transformer on
     * this JDK — it is absent from both the load-time path and the already-loaded sweep — so an
     * agent that simply declares a matcher for it silently instruments nothing. Touching the
     * class first puts it in {@code getAllLoadedClasses}, where the retransformation sweep does
     * pick it up.
     *
     * <p>Loading a JDK class the application was going to load anyway costs a few microseconds
     * of startup and changes no behaviour.
     */
    private static final String[] PRELOAD_FOR_RETRANSFORMATION = {
        "java.io.ObjectInputStream",
    };

    private static void preloadForRetransformation() {
        for (String name : PRELOAD_FOR_RETRANSFORMATION) {
            try {
                Class.forName(name, false, null);
            } catch (ClassNotFoundException | LinkageError ignored) {
                // A JDK without the type is a coverage gap, never a startup failure.
            }
        }
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
        preloadForRetransformation();
        AgentBuilder builder =
                new AgentBuilder.Default()
                        .disableClassFormatChanges()
                        .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
                        // One class per batch. The default retransforms every already-loaded
                        // type in a single call, so one type the JVM refuses to modify takes
                        // the whole sweep down with it — and the default redefinition listener
                        // swallows that, leaving an agent that reports itself healthy while
                        // half its instrumentation is missing.
                        .with(AgentBuilder.RedefinitionStrategy.BatchAllocator.ForFixedSize.ofSize(1))
                        .with(new RedefinitionFailureListener())
                        .with(new FailSafeListener())
                        // One call, not three. `ignore` *replaces* its matcher rather than
                        // adding to it, so chaining left only the last one in force — and the
                        // agent was instrumenting its own classes and Byte Buddy's, relying on
                        // the re-entrancy guard to survive it.
                        .ignore(
                                ElementMatchers.<TypeDescription>nameStartsWith("dev.aegis.")
                                        .or(ElementMatchers.nameStartsWith("net.bytebuddy."))
                                        .or(ElementMatchers.nameStartsWith("jdk.internal.")));

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
        builder = installSinkTransformers(builder);
        builder = installSanitizerTransformers(builder);

        builder.installOn(instrumentation);
    }

    /**
     * Attach one advice to the methods of one type.
     *
     * <p>Byte Buddy's fluent form nests four levels deep per registration, which turns a list of
     * sinks — the thing a reader most needs to be able to scan — into a wall. This says the same
     * thing on one line.
     */
    private static AgentBuilder advise(
            AgentBuilder builder,
            net.bytebuddy.matcher.ElementMatcher.Junction<TypeDescription> type,
            Class<?> advice,
            net.bytebuddy.matcher.ElementMatcher.Junction<
                            net.bytebuddy.description.method.MethodDescription>
                    methods) {
        return builder.type(type)
                .transform(
                        (b, described, loader, module, pd) ->
                                b.visit(net.bytebuddy.asm.Advice.to(advice).on(methods)));
    }

    /** Matches implementations of an interface, cheaply, via a name pre-filter. */
    private static net.bytebuddy.matcher.ElementMatcher.Junction<TypeDescription> implementing(
            String nameHint, String... interfaces) {
        return ElementMatchers.<TypeDescription>nameContains(nameHint)
                .and(ElementMatchers.hasSuperType(ElementMatchers.namedOneOf(interfaces)));
    }

    /**
     * The remaining sink families.
     *
     * <p>Declaring eleven rule classes and detecting three is worse than declaring three: it puts
     * a number on a report that the engine cannot stand behind. Each of these closes one.
     */
    private static AgentBuilder installSinkTransformers(AgentBuilder builder) {
        // Reflected XSS. The response body is written through a Writer that has no idea it
        // belongs to a response, so the channel is remembered when the response hands it out
        // and the write is checked against it by identity.
        net.bytebuddy.matcher.ElementMatcher.Junction<TypeDescription> httpResponse =
                implementing(
                        "Response",
                        "jakarta.servlet.http.HttpServletResponse",
                        "javax.servlet.http.HttpServletResponse");

        builder =
                advise(
                        builder,
                        httpResponse,
                        Advices.ResponseChannel.class,
                        ElementMatchers.namedOneOf("getWriter", "getOutputStream")
                                .and(ElementMatchers.takesNoArguments()));
        builder =
                advise(
                        builder,
                        implementing("Writer", "java.io.Writer"),
                        Advices.ResponseWrite.class,
                        ElementMatchers.namedOneOf("write", "print", "println")
                                .and(ElementMatchers.takesArgument(0, String.class)));

        // Open redirect and header injection, on the same response.
        builder =
                advise(
                        builder,
                        httpResponse,
                        Advices.Redirect.class,
                        ElementMatchers.named("sendRedirect")
                                .and(ElementMatchers.takesArgument(0, String.class)));
        builder =
                advise(
                        builder,
                        httpResponse,
                        Advices.ResponseHeader.class,
                        ElementMatchers.namedOneOf("setHeader", "addHeader")
                                .and(ElementMatchers.takesArguments(String.class, String.class)));

        // Server-side request forgery.
        builder =
                advise(
                        builder,
                        ElementMatchers.named("java.net.URL"),
                        Advices.UrlConstruction.class,
                        ElementMatchers.isConstructor()
                                .and(ElementMatchers.takesArgument(0, String.class)));

        // LDAP: the filter, not the name, is where injection lives.
        builder =
                advise(
                        builder,
                        implementing("Ctx", "javax.naming.directory.DirContext")
                                .or(implementing("Context", "javax.naming.directory.DirContext")),
                        Advices.LdapSearch.class,
                        ElementMatchers.named("search")
                                .and(ElementMatchers.takesArgument(1, String.class)));

        // XPath.
        builder =
                advise(
                        builder,
                        implementing("XPath", "javax.xml.xpath.XPath"),
                        Advices.XPathEvaluate.class,
                        ElementMatchers.namedOneOf("compile", "evaluate")
                                .and(ElementMatchers.takesArgument(0, String.class)));

        // Log injection: a forged line in an audit log is how an attacker edits history.
        builder =
                advise(
                        builder,
                        implementing("Logger", "org.slf4j.Logger")
                                .or(ElementMatchers.named("java.util.logging.Logger")),
                        Advices.LogWrite.class,
                        ElementMatchers.namedOneOf(
                                        "info", "warn", "warning", "error", "severe", "debug",
                                        "trace")
                                .and(ElementMatchers.takesArgument(0, String.class)));

        return installDeserializationTransformers(builder);
    }

    /**
     * Unsafe deserialization, and the object-level propagation it needs.
     *
     * <p>The only sink whose dangerous value is not a string. Taint arrives as a parameter,
     * becomes bytes, becomes a stream, and only then reaches {@code readObject} — so the chain
     * has to be tracked through three objects that are not text at all. A table that only ever
     * holds strings cannot see this attack, which is why the tracker is keyed on object identity
     * rather than on character data.
     */
    private static AgentBuilder installDeserializationTransformers(AgentBuilder builder) {
        builder =
                advise(
                        builder,
                        ElementMatchers.named("java.lang.String"),
                        Advices.DerivedFromThis.class,
                        // `returns` is not decoration. String.getBytes has a void overload, and
                        // an advice declaring @Advice.Return cannot be applied to it — which
                        // fails the transformation of java.lang.String *as a whole*, silently
                        // taking concat, substring and every other propagator down with it.
                        ElementMatchers.named("getBytes")
                                .and(ElementMatchers.returns(byte[].class)));
        builder =
                advise(
                        builder,
                        ElementMatchers.named("java.io.ByteArrayInputStream"),
                        Advices.DerivedFromArgument.class,
                        ElementMatchers.isConstructor()
                                .and(ElementMatchers.takesArgument(0, byte[].class)));
        builder =
                advise(
                        builder,
                        ElementMatchers.named("java.io.ObjectInputStream"),
                        Advices.DeserializeConstruct.class,
                        ElementMatchers.isConstructor()
                                .and(
                                        ElementMatchers.takesArgument(
                                                0, java.io.InputStream.class)));
        return advise(
                builder,
                ElementMatchers.named("java.io.ObjectInputStream"),
                Advices.Deserialize.class,
                ElementMatchers.named("readObject").and(ElementMatchers.takesNoArguments()));
    }

    /**
     * Encoders, which clear taint for the rule class they actually address — and only that one.
     *
     * <p>Without these the new sinks would fire on correct code, and a tool that flags correct
     * code is a tool that gets switched off. HTML-escaping a value makes it safe to render and
     * does nothing whatsoever to make it safe to concatenate into SQL (ADR-0007).
     *
     * <p>The third-party encoders are matched by name and are simply absent when a customer does
     * not use them. Matching a library we do not depend on costs nothing and is the only way to
     * recognise the encoder they actually reach for.
     */
    private static AgentBuilder installSanitizerTransformers(AgentBuilder builder) {
        builder =
                advise(
                        builder,
                        ElementMatchers.named("java.net.URLEncoder"),
                        Advices.UrlEncode.class,
                        ElementMatchers.named("encode")
                                .and(ElementMatchers.takesArgument(0, String.class))
                                .and(ElementMatchers.returns(String.class)));

        builder =
                advise(
                        builder,
                        ElementMatchers.namedOneOf(
                                "org.apache.commons.text.StringEscapeUtils",
                                "org.apache.commons.lang3.StringEscapeUtils",
                                "org.apache.commons.lang.StringEscapeUtils",
                                "org.springframework.web.util.HtmlUtils",
                                "org.owasp.encoder.Encode"),
                        Advices.HtmlEscape.class,
                        ElementMatchers.<net.bytebuddy.description.method.MethodDescription>
                                        nameStartsWith("escapeHtml")
                                .or(ElementMatchers.nameStartsWith("escapeXml"))
                                .or(ElementMatchers.nameStartsWith("escapeEcmaScript"))
                                .or(ElementMatchers.nameStartsWith("htmlEscape"))
                                .or(ElementMatchers.nameStartsWith("forHtml"))
                                .or(ElementMatchers.nameStartsWith("forJavaScript"))
                                .and(ElementMatchers.takesArgument(0, String.class))
                                .and(ElementMatchers.returns(String.class)));

        return advise(
                builder,
                implementing("Encoder", "org.owasp.esapi.Encoder")
                        .or(ElementMatchers.named("org.owasp.encoder.Encode")),
                Advices.QueryEncode.class,
                ElementMatchers.<net.bytebuddy.description.method.MethodDescription>namedOneOf(
                                "encodeForLDAP", "encodeForDN", "encodeForXPath", "forXmlContent")
                        .and(ElementMatchers.takesArgument(0, String.class))
                        .and(ElementMatchers.returns(String.class)));
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
    /** Surfaces failures in the retransformation sweep, which are otherwise silent. */
    static final class RedefinitionFailureListener
            extends AgentBuilder.RedefinitionStrategy.Listener.Adapter {
        @Override
        public Iterable<? extends java.util.List<Class<?>>> onError(
                int index,
                java.util.List<Class<?>> batch,
                Throwable throwable,
                java.util.List<Class<?>> types) {
            if (Boolean.getBoolean("aegis.debug")) {
                System.err.println("[aegis] retransformation failed for " + batch + ": " + throwable);
            }
            return java.util.Collections.emptyList();
        }
    }

    static final class FailSafeListener extends AgentBuilder.Listener.Adapter {

        /**
         * Types whose loss silently guts the taint engine.
         *
         * <p>A failure on an application class is a small gap. A failure on one of these means
         * the agent is running, reporting itself healthy, and detecting nothing — which is how
         * a broken `getBytes` matcher cost the whole of `java.lang.String`, and with it every
         * propagator on it, while the suite still showed an installed agent.
         */
        private static final java.util.Set<String> LOAD_BEARING =
                java.util.Set.of(
                        "java.lang.String",
                        "java.lang.StringBuilder",
                        "java.lang.StringBuffer",
                        "java.lang.invoke.StringConcatFactory",
                        "java.io.ObjectInputStream");

        @Override
        public void onError(
                String typeName,
                ClassLoader classLoader,
                JavaModule module,
                boolean loaded,
                Throwable throwable) {
            if (LOAD_BEARING.contains(typeName)) {
                // Reported, not merely logged: an application with poor instrumentation coverage
                // and no findings must read as *unknown*, never as *secure* (ADR-0007).
                reportCoverageGap(typeName, throwable);
            }
            if (Boolean.getBoolean("aegis.debug")) {
                System.err.println("[aegis] could not instrument " + typeName + ": " + throwable);
            }
        }

        private static void reportCoverageGap(String typeName, Throwable throwable) {
            try {
                Class<?> runtimeClass = Class.forName("dev.aegis.agent.AgentRuntime", true, null);
                Object runtime = runtimeClass.getMethod("get").invoke(null);
                if (runtime == null) {
                    return;
                }
                Object reporter = runtimeClass.getMethod("reporter").invoke(runtime);
                reporter.getClass()
                        .getMethod("reportCoverageGap", String.class, String.class)
                        .invoke(
                                reporter,
                                "instrumentation failed: " + throwable,
                                typeName);
            } catch (ReflectiveOperationException | RuntimeException ignored) {
                // Reporting the gap must not itself become a failure path.
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
