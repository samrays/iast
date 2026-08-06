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

    /**
     * {@code ServletRequest.getInputStream/getReader} — marks the returned stream itself, so a
     * propagator downstream can carry the mark to whatever it derives. See
     * {@link dev.aegis.agent.AgentRuntime#onRequestBodySource}.
     */
    public static final class RequestBodyAccess {
        private RequestBodyAccess() {}

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(@Advice.Return Object stream) {
            AgentRuntime.onRequestBodySource(stream);
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

    /** {@code String.split(regex)} — every piece derives from the string that was split. */
    public static final class Split {
        private Split() {}

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(@Advice.This Object self, @Advice.Return Object[] pieces) {
            AgentRuntime.onSplit(pieces, self);
        }
    }

    /** {@code URLDecoder.decode} and other whole-value rewrites. */
    public static final class Reshaping {
        private Reshaping() {}

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(
                @Advice.Argument(0) Object source, @Advice.Return String result) {
            AgentRuntime.onReshapingTransform(result, source);
        }
    }

    /** {@code ServletRequest.getHeaders(name)} — wrap so each element is tainted when taken. */
    public static final class HeaderEnumeration {
        private HeaderEnumeration() {}

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(
                @Advice.Argument(0) String name,
                @Advice.Return(readOnly = false) java.util.Enumeration<?> values) {
            values = AgentRuntime.onHeaderEnumeration(values, name);
        }
    }

    /**
     * {@code Connection.prepareStatement(sql)} and {@code prepareCall(sql)}.
     *
     * <p>A prepared statement is only safe because its <em>parameters</em> are bound. Its query
     * text is not, and a concatenated string handed to {@code prepareStatement} is exactly as
     * injectable as one handed to {@code Statement.execute} — a distinction that cost 80 missed
     * defects on the OWASP Benchmark before this existed.
     */
    public static final class JdbcPrepare {
        private JdbcPrepare() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Argument(0) Object sql) {
            AgentRuntime.onSink(
                    sql, RuleClass.SQL_INJECTION, "java.sql.Connection#prepareStatement(String)");
        }
    }

    /** {@code ProcessBuilder.start()} — every path that builds a command ends here. */
    public static final class ProcessStart {
        private ProcessStart() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.This ProcessBuilder builder) {
            AgentRuntime.onProcessStart(builder);
        }
    }

    /** {@code PrintWriter.format/printf} into the response body. */
    public static final class ResponseFormat {
        private ResponseFormat() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(
                @Advice.This Object target, @Advice.AllArguments Object[] arguments) {
            AgentRuntime.onResponseFormat(target, arguments);
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

    /**
     * {@code File(File parent, String child)} and {@code File(String parent, String child)}.
     *
     * <p>{@code new File(uploadDirectory, attackerName)} is the ordinary way Java code builds a
     * path from a fixed base plus user input — it is what WebGoat's own upload lesson does, and
     * the single-argument {@link FileAccess} advice above never sees it: argument 0 there is the
     * {@code File} parent, not the attacker-controlled child. Both arguments are checked rather
     * than assuming which one is untrusted; {@link AgentRuntime#onSink} already no-ops on a
     * non-{@code String} argument, so calling it on the parent when the parent is a {@code File}
     * costs one wasted instanceof check, not a false positive.
     */
    public static final class FileConstructWithParent {
        private FileConstructWithParent() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(
                @Advice.Argument(0) Object parent, @Advice.Argument(1) Object child) {
            AgentRuntime.onSink(
                    parent, RuleClass.PATH_TRAVERSAL, "java.io.File#<init>(.., String)");
            AgentRuntime.onSink(
                    child, RuleClass.PATH_TRAVERSAL, "java.io.File#<init>(.., String)");
        }
    }

    /** {@code DirContext.search(name, filter, ...)} — the filter is the injection point. */
    public static final class LdapSearch {
        private LdapSearch() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Argument(1) Object filter) {
            AgentRuntime.onSink(
                    filter,
                    RuleClass.LDAP_INJECTION,
                    "javax.naming.directory.DirContext#search(String,String,..)");
        }
    }

    /** {@code XPath.compile/evaluate(String)}. */
    public static final class XPathEvaluate {
        private XPathEvaluate() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Argument(0) Object expression) {
            AgentRuntime.onSink(
                    expression,
                    RuleClass.XPATH_INJECTION,
                    "javax.xml.xpath.XPath#evaluate(String,..)");
        }
    }

    /** {@code new URL(String)} and {@code URI.create(String)} — server-side request forgery. */
    public static final class UrlConstruction {
        private UrlConstruction() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Argument(0) Object target) {
            AgentRuntime.onSink(target, RuleClass.SSRF, "java.net.URL#<init>(String)");
        }
    }

    /** {@code HttpServletResponse.sendRedirect(String)}. */
    public static final class Redirect {
        private Redirect() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Argument(0) Object location) {
            AgentRuntime.onSink(
                    location,
                    RuleClass.OPEN_REDIRECT,
                    "jakarta.servlet.http.HttpServletResponse#sendRedirect(String)");
        }
    }

    /**
     * {@code setHeader/addHeader(name, value)}.
     *
     * <p>Both arguments are checked. A tainted header <em>name</em> is the more dangerous of the
     * two and the one people forget.
     */
    public static final class ResponseHeader {
        private ResponseHeader() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(
                @Advice.Argument(0) Object name, @Advice.Argument(1) Object value) {
            AgentRuntime.onSink(
                    name,
                    RuleClass.HEADER_INJECTION,
                    "jakarta.servlet.http.HttpServletResponse#setHeader(String,String)");
            AgentRuntime.onSink(
                    value,
                    RuleClass.HEADER_INJECTION,
                    "jakarta.servlet.http.HttpServletResponse#setHeader(String,String)");
        }
    }

    /** {@code Logger.info/warn/error(String)} — SLF4J, Log4j and {@code java.util.logging}. */
    public static final class LogWrite {
        private LogWrite() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Argument(0) Object message) {
            AgentRuntime.onSink(message, RuleClass.LOG_INJECTION, "org.slf4j.Logger#info(String)");
        }
    }

    /**
     * {@code new ObjectInputStream(in)} — handing Java serialization an attacker's stream.
     *
     * <p>The construction, not the {@code readObject}, because the constructor already reads and
     * validates the stream header: a hostile payload that is not well-formed throws there, and a
     * sink placed on {@code readObject} would never see the attempt at all.
     */
    public static final class DeserializeConstruct {
        private DeserializeConstruct() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Argument(0) Object source) {
            AgentRuntime.onObjectSink(
                    source,
                    RuleClass.UNSAFE_DESERIALIZATION,
                    "java.io.ObjectInputStream#<init>(InputStream)");
        }
    }

    /** {@code ObjectInputStream.readObject()}, for a stream that was well-formed enough to open. */
    public static final class Deserialize {
        private Deserialize() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.This Object stream) {
            AgentRuntime.onObjectSink(
                    stream,
                    RuleClass.UNSAFE_DESERIALIZATION,
                    "java.io.ObjectInputStream#readObject()");
        }
    }

    /**
     * {@code XMLInputFactory#createXMLStreamReader(Reader|InputStream)} — the StAX entry point.
     *
     * <p>Not just the raw JDK API: Jackson's {@code XmlMapper} builds its parser on top of
     * exactly this call, so instrumenting it here also covers every application that reads XML
     * through Jackson without adding a Jackson-specific hook. {@code XMLInputFactory.newInstance()}
     * has DTD and external-entity support on by default, and disabling them is opt-in — matching
     * the unsafe-deserialization sink two entries up, this fires on the dataflow and does not
     * try to detect whether that opt-in happened, the same way {@code readObject} does not try
     * to detect an installed {@code ObjectInputFilter}.
     */
    public static final class XmlStreamRead {
        private XmlStreamRead() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Argument(0) Object source) {
            AgentRuntime.onObjectSink(
                    source,
                    RuleClass.XXE,
                    "javax.xml.stream.XMLInputFactory#createXMLStreamReader");
        }
    }

    /** {@code DocumentBuilder#parse(InputStream)} — the classic DOM-based XXE shape. */
    public static final class DocumentParse {
        private DocumentParse() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Argument(0) Object source) {
            AgentRuntime.onObjectSink(
                    source, RuleClass.XXE, "javax.xml.parsers.DocumentBuilder#parse");
        }
    }

    // --- response body, for reflected XSS ---------------------------------------------------

    /** {@code ServletResponse.getWriter()/getOutputStream()} — remember the body channel. */
    public static final class ResponseChannel {
        private ResponseChannel() {}

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(@Advice.Return Object channel) {
            AgentRuntime.onResponseChannel(channel);
        }
    }

    /**
     * {@code Writer.write/print/println(String)}.
     *
     * <p>Fires for every writer in the process and reports for exactly one: the object this
     * request's response handed out. Matching on the writer's type instead would either miss
     * the container's own subclass or flag {@code System.out}.
     */
    public static final class ResponseWrite {
        private ResponseWrite() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.This Object target, @Advice.Argument(0) Object value) {
            AgentRuntime.onResponseWrite(target, value);
        }
    }

    // --- sanitizers -------------------------------------------------------------------------

    /**
     * {@code URLEncoder.encode(String, ...)}.
     *
     * <p>Clears the URL-context rules and nothing else. Percent-encoding makes a value safe in a
     * URL or a header and does precisely nothing for HTML or SQL — treating "sanitized" as one
     * global flag is how an engine misses the injection that matters (ADR-0007).
     */
    public static final class UrlEncode {
        private UrlEncode() {}

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(
                @Advice.Argument(0) Object source, @Advice.Return String result) {
            AgentRuntime.onUrlEncoded(result, source);
        }
    }

    /** An HTML or XML escaper: Apache commons-text, Spring's HtmlUtils, the OWASP encoder. */
    public static final class HtmlEscape {
        private HtmlEscape() {}

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(
                @Advice.Argument(0) Object source, @Advice.Return String result) {
            AgentRuntime.onHtmlEscaped(result, source);
        }
    }

    /** An LDAP or XPath encoder. */
    public static final class QueryEncode {
        private QueryEncode() {}

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(
                @Advice.Argument(0) Object source, @Advice.Return String result) {
            AgentRuntime.onQueryEncoded(result, source);
        }
    }

    // --- object-level propagation ------------------------------------------------------------

    /** {@code String.getBytes()}, and streams wrapping a tainted buffer. */
    public static final class DerivedFromThis {
        private DerivedFromThis() {}

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(@Advice.This Object source, @Advice.Return Object derived) {
            AgentRuntime.onDerivedObject(derived, source);
        }
    }

    /** A constructor taking a tainted argument, e.g. {@code new ByteArrayInputStream(bytes)}. */
    public static final class DerivedFromArgument {
        private DerivedFromArgument() {}

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(@Advice.This Object derived, @Advice.Argument(0) Object source) {
            AgentRuntime.onDerivedObject(derived, source);
        }
    }

    /**
     * {@code Base64.Decoder#decode(String)} / {@code decode(byte[])}.
     *
     * <p>An attacker-controlled payload almost never arrives as raw bytes — it arrives as a
     * base64 string in a parameter, header or cookie, and the application decodes it before
     * doing anything dangerous with it. {@code Base64.getDecoder()} returns a shared singleton,
     * so unlike {@link DerivedFromThis} the derived value cannot be read off {@code this}; it
     * has to be read off the return value instead, carrying taint from argument to result the
     * way {@code Reshaping} does for {@code URLDecoder}. Without this the taint dies at the
     * decode call and every downstream sink — deserialization above all — sees clean bytes.
     */
    public static final class Base64Decode {
        private Base64Decode() {}

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(
                @Advice.Argument(0) Object source, @Advice.Return Object derived) {
            AgentRuntime.onDerivedObject(derived, source);
        }
    }

    /**
     * Whole-body-to-string utilities: {@code StreamUtils.copyToString}, the call Spring's own
     * {@code StringHttpMessageConverter} makes to satisfy a {@code @RequestBody String}
     * parameter — confirmed by decompiling the bundled {@code spring-web} jar, not assumed.
     * Without this a POST body never becomes tainted at all: Spring reads it entirely inside
     * framework code, past every accessor-based source above.
     */
    public static final class StreamToString {
        private StreamToString() {}

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(
                @Advice.Argument(0) Object source, @Advice.Return Object derived) {
            AgentRuntime.onDerivedObject(derived, source);
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
