package dev.aegis.agent.instrument;

import dev.aegis.agent.AgentRuntime;
import dev.aegis.agent.taint.RuleClass;
import net.bytebuddy.asm.Advice;

/**
 * The bytecode that Byte Buddy inlines into instrumented methods.
 *
 * <p>Advice bodies are copied verbatim into the application's own methods, which imposes real
 * constraints: no captured state, no lambdas, no {@code try} around the whole body, and every
 * referenced class must be reachable from the instrumented class's loader. They are kept as
 * thin as possible — a single static call into {@link AgentRuntime}, which owns the fail-open
 * wrapper and all the actual logic.
 */
public final class Advices {

    private Advices() {}

    // --- HTTP entry point and sources ------------------------------------------------------

    /**
     * {@code HttpServlet.service(...)} — the boundary of one request.
     *
     * <p>Opens the request context on the way in and closes it on the way out, including when
     * the application throws. Everything downstream — every source, every propagation step,
     * every sink evaluation — is scoped to the context this pair creates.
     */
    public static final class HttpEntry {
        private HttpEntry() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static boolean enter(@Advice.Argument(0) Object request) {
            return AgentRuntime.onRequestEnter(request);
        }

        /**
         * {@code onThrowable} matters as much as the normal path: a servlet that throws still
         * has to release its taint table, or the next request on that pooled thread inherits
         * it.
         */
        @Advice.OnMethodExit(suppress = Throwable.class, onThrowable = Throwable.class)
        public static void exit(@Advice.Enter boolean owner, @Advice.Argument(0) Object request) {
            AgentRuntime.onRequestExit(owner, request);
        }
    }

    /**
     * {@code ServletRequest.getParameter/getHeader/getQueryString/...} — where attacker data
     * enters.
     *
     * <p>One advice for the whole family, dispatched on the method name. Each distinct advice
     * class is a distinct block of bytecode pasted into a container class that runs on every
     * request; sharing one keeps that footprint small.
     */
    public static final class HttpStringSource {
        private HttpStringSource() {}

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(
                @Advice.Origin("#m") String accessor,
                @Advice.AllArguments Object[] arguments,
                @Advice.Return Object result) {
            AgentRuntime.onHttpSource(accessor, arguments, result);
        }
    }

    /** {@code Cookie.getValue()}. */
    public static final class CookieValue {
        private CookieValue() {}

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(@Advice.This Object cookie, @Advice.Return String value) {
            AgentRuntime.onCookieValue(cookie, value);
        }
    }

    /** {@code ServletRequest.getInputStream/getReader} — a blind spot, reported as one. */
    public static final class RequestBodyAccess {
        private RequestBodyAccess() {}

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(@Advice.Origin("#m") String accessor) {
            AgentRuntime.onRequestBodyAccess(accessor);
        }
    }

    // --- propagators --------------------------------------------------------------------

    /** {@code String.concat(String)}. */
    public static final class StringConcat {
        private StringConcat() {}

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(
                @Advice.This Object self,
                @Advice.Argument(0) Object argument,
                @Advice.Return String result) {
            AgentRuntime.onConcat(result, self, argument);
        }
    }

    /**
     * {@code StringBuilder.append(...)}.
     *
     * <p>Captures the builder's <em>length</em> before the append, so the range arithmetic knows
     * where the appended value lands. Reading it afterwards would give the combined length and
     * shift every range by the wrong amount.
     *
     * <p>The length, emphatically not the content. This advice is inlined into
     * {@code java.lang.StringBuilder}, so it runs for every append in the entire process —
     * the container's, the framework's, the JDK's. Calling {@code toString()} here copies the
     * whole buffer and allocates a String each time, turning an O(1) append into O(n) and
     * making assembly of a long string quadratic. It measured as the single largest cost in
     * the agent.
     */
    public static final class BuilderAppend {
        private BuilderAppend() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static int enter(@Advice.This CharSequence self) {
            return self.length();
        }

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(
                @Advice.Enter int lengthBefore,
                @Advice.This Object self,
                @Advice.Argument(0) Object argument) {
            AgentRuntime.onBuilderAppend(self, lengthBefore, argument);
        }
    }

    /**
     * {@code StringConcatFactory.makeConcatWithConstants(...)} — the bootstrap for {@code +}.
     *
     * <p>Since Java 9, {@code "a" + b} is an {@code invokedynamic}, not a {@code StringBuilder}.
     * Rewriting the call site here — once, when it links — is the only way to see the most
     * common shape of injection in the language.
     */
    public static final class ConcatFactoryWithConstants {
        private ConcatFactoryWithConstants() {}

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(
                @Advice.Argument(0) java.lang.invoke.MethodHandles.Lookup lookup,
                @Advice.Argument(3) String recipe,
                @Advice.Argument(4) Object[] constants,
                @Advice.Return(readOnly = false) java.lang.invoke.CallSite site) {
            site =
                    AgentRuntime.wrapConcat(
                            site, lookup.lookupClass().getName(), recipe, constants);
        }
    }

    /** {@code StringConcatFactory.makeConcat(...)} — the same, with no interleaved constants. */
    public static final class ConcatFactory {
        private ConcatFactory() {}

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(
                @Advice.Argument(0) java.lang.invoke.MethodHandles.Lookup lookup,
                @Advice.Return(readOnly = false) java.lang.invoke.CallSite site) {
            site = AgentRuntime.wrapConcat(site, lookup.lookupClass().getName(), null, null);
        }
    }

    /** {@code StringBuilder.toString()} — materializes the builder's accumulated taint. */
    public static final class BuilderToString {
        private BuilderToString() {}

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(@Advice.This Object self, @Advice.Return String result) {
            AgentRuntime.onPreservingTransform(result, self);
        }
    }

    /** {@code String.substring(int)} and {@code String.substring(int, int)}. */
    public static final class Substring {
        private Substring() {}

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(
                @Advice.This Object self,
                @Advice.Argument(0) int from,
                @Advice.Return String result) {
            AgentRuntime.onSubstring(result, self, from, from + (result == null ? 0 : result.length()));
        }
    }

    /** {@code toLowerCase}, {@code toUpperCase}, {@code trim}, {@code intern}, {@code strip}. */
    public static final class Preserving {
        private Preserving() {}

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(@Advice.This Object self, @Advice.Return String result) {
            AgentRuntime.onPreservingTransform(result, self);
        }
    }

    // --- sinks --------------------------------------------------------------------------

    /**
     * {@code Statement.execute*(String)}.
     *
     * <p>{@code PreparedStatement} does not go through here — its SQL is fixed at creation
     * and its parameters are bound, which is exactly the flow that must produce no finding.
     */
    public static final class JdbcStatement {
        private JdbcStatement() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Argument(0) Object sql) {
            AgentRuntime.onSink(sql, RuleClass.SQL_INJECTION, "java.sql.Statement#execute(String)");
        }
    }

    /** {@code Runtime.exec(String)} and {@code ProcessBuilder.command(...)}. */
    public static final class CommandExec {
        private CommandExec() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Argument(0) Object command) {
            AgentRuntime.onSink(
                    command, RuleClass.COMMAND_INJECTION, "java.lang.Runtime#exec(String)");
        }
    }

    /** {@code new File(String)} and {@code Paths.get(String, ...)}. */
    public static final class FileAccess {
        private FileAccess() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Argument(0) Object path) {
            AgentRuntime.onSink(path, RuleClass.PATH_TRAVERSAL, "java.io.File#<init>(String)");
        }
    }

    // --- async context propagation -------------------------------------------------------

    /**
     * {@code Executor.execute(Runnable)} — wrap the task so the request context follows it.
     *
     * <p>Without this, taint dies at the first thread hand-off and the agent silently
     * under-reports on exactly the asynchronous codebases that most need checking.
     */
    public static final class ExecutorSubmit {
        private ExecutorSubmit() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(
                @Advice.Argument(value = 0, readOnly = false) Runnable task) {
            task = AgentRuntime.wrapForHandoff(task);
        }
    }

    /**
     * {@code ExecutorService.submit(Callable)} and {@code ForkJoinPool.submit(Callable)}.
     *
     * <p>{@code AbstractExecutorService.submit} funnels through {@code execute}, so most pools
     * are already covered by {@link ExecutorSubmit}. {@code ForkJoinPool} is the exception: it
     * overrides {@code submit} and pushes straight onto a work queue, which is precisely the
     * pool {@code CompletableFuture} and parallel streams use by default.
     */
    public static final class CallableSubmit {
        private CallableSubmit() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(
                @Advice.Argument(value = 0, readOnly = false) java.util.concurrent.Callable<?> task) {
            task = AgentRuntime.wrapForHandoff(task);
        }
    }
}
