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
     * <p>Captures the builder's content <em>before</em> the append so the range arithmetic
     * knows where the appended value lands. Reading it afterwards would give the combined
     * length and shift every range by the wrong amount.
     */
    public static final class BuilderAppend {
        private BuilderAppend() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static String enter(@Advice.This Object self) {
            return self.toString();
        }

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(
                @Advice.Enter String before,
                @Advice.This Object self,
                @Advice.Argument(0) Object argument) {
            AgentRuntime.onBuilderAppend(self, before, argument);
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
}
