package com.example.corpus;

import com.example.app.UserRepository;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.naming.directory.InitialDirContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.xpath.XPathFactory;
import org.apache.commons.text.StringEscapeUtils;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.InputSource;

/**
 * The detection corpus: paired vulnerable and safe cases, modelled on the OWASP Benchmark.
 *
 * <p>A scanner that reports everything catches every vulnerability and is worthless. The pairing
 * is the whole design — each vulnerable case has a sibling that differs only in the one thing
 * that makes it safe, so the suite measures the two numbers that actually decide whether a
 * customer leaves the product switched on: did it find the real defects, and did it stay quiet
 * on the correct code?
 *
 * <p>Every case is driven over real HTTP through a real servlet container under a real
 * {@code -javaagent}. The application declares nothing to the agent.
 */
public final class BenchmarkApp {

    private static final Logger LOG = LoggerFactory.getLogger(BenchmarkApp.class);

    /** The verdict a case is expected to produce. */
    public enum Expectation {
        VULNERABLE,
        SAFE
    }

    /** Percent-encoded {@code ' OR 1=1--}. */
    private static final String SQL_PAYLOAD = "%27%20OR%201%3D1--";
    /** Percent-encoded {@code ; cat /etc/passwd}. */
    private static final String CMD_PAYLOAD = "%3B%20cat%20%2Fetc%2Fpasswd";
    /** Percent-encoded {@code ../../etc/passwd}. */
    private static final String PATH_PAYLOAD = "..%2F..%2Fetc%2Fpasswd";
    /** Percent-encoded {@code <script>alert(1)</script>}. */
    private static final String XSS_PAYLOAD = "%3Cscript%3Ealert(1)%3C%2Fscript%3E";
    /** Percent-encoded {@code //evil.example.com}. */
    private static final String REDIRECT_PAYLOAD = "%2F%2Fevil.example.com";
    /** {@code x)(uid=*} — closes the filter term and opens a wildcard. */
    private static final String LDAP_PAYLOAD = "x)(uid%3D*";
    /** Percent-encoded {@code ' or '1'='1}. */
    private static final String XPATH_PAYLOAD = "%27%20or%20%271%27%3D%271";
    /** A newline, so the forged line looks like its own log record. */
    private static final String LOG_PAYLOAD = "admin%0AWARN%20access%20granted";
    /**
     * Not percent-encoded, unlike every payload above: this one is sent as a raw POST body, not
     * a query parameter, so it must not be URL-encoded — nothing on this path would decode it.
     */
    private static final String SQL_PAYLOAD_RAW = "' OR 1=1--";
    /** A full document, not a single metacharacter — too irregular to hand-encode reliably. */
    private static final String XXE_PAYLOAD =
            URLEncoder.encode(
                    "<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><x>&e;</x>",
                    StandardCharsets.UTF_8);

    /** Path → expected verdict, the rule that must fire, and the payload to send. */
    public static final Map<String, String[]> CASES = new LinkedHashMap<>();

    static {
        // --- SQL injection ----------------------------------------------------------------
        register("/sql/builder", Expectation.VULNERABLE, "sql-injection", SQL_PAYLOAD);
        register("/sql/plus", Expectation.VULNERABLE, "sql-injection", SQL_PAYLOAD);
        register("/sql/concat", Expectation.VULNERABLE, "sql-injection", SQL_PAYLOAD);
        register("/sql/substring", Expectation.VULNERABLE, "sql-injection", SQL_PAYLOAD);
        register("/sql/builder-replace", Expectation.VULNERABLE, "sql-injection", SQL_PAYLOAD);
        register("/sql/builder-reverse", Expectation.VULNERABLE, "sql-injection", SQL_PAYLOAD);
        register("/sql/format", Expectation.VULNERABLE, "sql-injection", SQL_PAYLOAD);
        register("/sql/formatted", Expectation.VULNERABLE, "sql-injection", SQL_PAYLOAD);
        // A real tainted flow with a benign payload. Detection should report CONFIRMED, while
        // blocking must let the query execute because exploitation was not confirmed.
        register("/sql/confirmed", Expectation.VULNERABLE, "sql-injection", "alice");
        register("/sql/builder-replace-clears", Expectation.SAFE, "", SQL_PAYLOAD);
        register("/sql/builder-reverse-constant", Expectation.SAFE, "", SQL_PAYLOAD);
        register("/sql/format-constant", Expectation.SAFE, "", SQL_PAYLOAD);
        register("/sql/formatted-constant", Expectation.SAFE, "", SQL_PAYLOAD);
        register("/sql/confirmed-constant", Expectation.SAFE, "", "alice");
        register("/sql/prepared", Expectation.SAFE, "", SQL_PAYLOAD);
        register("/sql/constant", Expectation.SAFE, "", SQL_PAYLOAD);
        register("/sql/identity", Expectation.SAFE, "", "alice");

        // --- Command injection ------------------------------------------------------------
        register("/cmd/exec", Expectation.VULNERABLE, "command-injection", CMD_PAYLOAD);
        register("/cmd/constant", Expectation.SAFE, "", CMD_PAYLOAD);

        // --- Path traversal ---------------------------------------------------------------
        register("/path/file", Expectation.VULNERABLE, "path-traversal", PATH_PAYLOAD);
        register("/path/constant", Expectation.SAFE, "", PATH_PAYLOAD);
        // `new File(base, name)` — the two-argument constructor, not the concatenated single
        // string above. This is the shape a real upload handler uses (WebGoat's among them),
        // and it is a distinct code path in the agent: argument 0 there is the base directory,
        // not the attacker's input, so the single-argument advice never sees it.
        register("/path/file-child", Expectation.VULNERABLE, "path-traversal", PATH_PAYLOAD);
        register("/path/file-child-constant", Expectation.SAFE, "", PATH_PAYLOAD);

        // --- Reflected XSS ----------------------------------------------------------------
        register("/xss/write", Expectation.VULNERABLE, "reflected-xss", XSS_PAYLOAD);
        register("/xss/escaped", Expectation.SAFE, "", XSS_PAYLOAD);
        // getRequestURI() is not a taint source (see AgentRuntime#sourceKindOf): it returns the
        // whole URI, context path included, and every framework reads it for reasons that have
        // nothing to do with the current request's attacker-controlled parts — Thymeleaf
        // resolving its own `@{...}` resource links being the one that produced a false
        // positive on WebGoat's favicon and stylesheets, on every page, from the first request.
        register("/xss/request-uri", Expectation.SAFE, "", XSS_PAYLOAD);

        // --- Open redirect ----------------------------------------------------------------
        register("/redirect/open", Expectation.VULNERABLE, "open-redirect", REDIRECT_PAYLOAD);
        register("/redirect/encoded", Expectation.SAFE, "", REDIRECT_PAYLOAD);

        // --- Header injection -------------------------------------------------------------
        register("/header/set", Expectation.VULNERABLE, "header-injection", XSS_PAYLOAD);
        register("/header/constant", Expectation.SAFE, "", XSS_PAYLOAD);
        register(
                "/header/name-to-sql",
                Expectation.VULNERABLE,
                "sql-injection",
                "X-Aegis-Probe");
        register("/header/name-constant", Expectation.SAFE, "", "X-Aegis-Probe");
        register(
                "/parameter/name-to-sql",
                Expectation.VULNERABLE,
                "sql-injection",
                "X-Aegis-Parameter");
        register("/parameter/name-constant", Expectation.SAFE, "", "X-Aegis-Parameter");

        // --- Server-side request forgery --------------------------------------------------
        register("/ssrf/url", Expectation.VULNERABLE, "ssrf", "evil.example.com");
        register("/ssrf/constant", Expectation.SAFE, "", "evil.example.com");

        // --- LDAP injection ---------------------------------------------------------------
        register("/ldap/search", Expectation.VULNERABLE, "ldap-injection", LDAP_PAYLOAD);
        register("/ldap/constant", Expectation.SAFE, "", LDAP_PAYLOAD);

        // --- XPath injection --------------------------------------------------------------
        register("/xpath/evaluate", Expectation.VULNERABLE, "xpath-injection", XPATH_PAYLOAD);
        register("/xpath/constant", Expectation.SAFE, "", XPATH_PAYLOAD);

        // --- Log injection ----------------------------------------------------------------
        register("/log/write", Expectation.VULNERABLE, "log-injection", LOG_PAYLOAD);
        register("/log/constant", Expectation.SAFE, "", LOG_PAYLOAD);

        // --- Unsafe deserialization -------------------------------------------------------
        register("/deser/read", Expectation.VULNERABLE, "unsafe-deserialization", "payload");
        register("/deser/constant", Expectation.SAFE, "", "payload");
        // Base64.getDecoder().decode(...) rather than String.getBytes() — the shape a real
        // attacker uses, since a serialized object travels as a base64 parameter, header or
        // cookie. A distinct propagator from the getBytes() case above; the payload here must
        // decode as valid base64, or the corpus process itself would fail before the sink runs.
        register(
                "/deser/base64",
                Expectation.VULNERABLE,
                "unsafe-deserialization",
                java.util.Base64.getEncoder()
                        .encodeToString("payload".getBytes(StandardCharsets.UTF_8)));
        register(
                "/deser/base64-constant",
                Expectation.SAFE,
                "",
                java.util.Base64.getEncoder()
                        .encodeToString("payload".getBytes(StandardCharsets.UTF_8)));

        // --- XML External Entity injection --------------------------------------------------
        // Two entry points, matching the two sinks: the classic DOM-based DocumentBuilder, and
        // StAX via XMLInputFactory — which is what WebGoat's own XXE lesson uses, and what
        // Jackson's XmlMapper is built on, so this one also proves the Jackson path works
        // without a Jackson-specific sink.
        register("/xxe/documentbuilder", Expectation.VULNERABLE, "xxe", XXE_PAYLOAD);
        register("/xxe/documentbuilder-constant", Expectation.SAFE, "", XXE_PAYLOAD);
        register("/xxe/stax", Expectation.VULNERABLE, "xxe", XXE_PAYLOAD);
        register("/xxe/stax-constant", Expectation.SAFE, "", XXE_PAYLOAD);

        // --- Request body as a source -------------------------------------------------------
        // getInputStream().readAllBytes() into new String(bytes, charset): the idiom that
        // covers raw servlet code, distinct from Spring's StreamUtils.copyToString, which the
        // corpus cannot exercise without adding spring-core as a test dependency — that path is
        // verified live, against WebGoat's own bundled Spring, instead.
        register("/body/sql", Expectation.VULNERABLE, "sql-injection", SQL_PAYLOAD_RAW);
        register("/body/sql-constant", Expectation.SAFE, "", SQL_PAYLOAD_RAW);

        // --- Cookie as a source -----------------------------------------------------------
        register("/cookie/sql", Expectation.VULNERABLE, "sql-injection", SQL_PAYLOAD);
        register("/split/first", Expectation.VULNERABLE, "sql-injection", SQL_PAYLOAD);
        register("/split/constant", Expectation.SAFE, "", SQL_PAYLOAD);
        register("/cookie/decoded", Expectation.VULNERABLE, "sql-injection", SQL_PAYLOAD);
        register("/cookie/constant", Expectation.SAFE, "", SQL_PAYLOAD);

        // --- Reads a source and reaches nothing -------------------------------------------
        register("/noop", Expectation.SAFE, "", SQL_PAYLOAD);
    }

    private static void register(
            String path, Expectation expectation, String rule, String payload) {
        CASES.put(path, new String[] {expectation.name(), rule, payload});
    }

    public static void main(String[] args) throws Exception {
        Class.forName("org.h2.Driver");
        try (Connection connection =
                DriverManager.getConnection("jdbc:h2:mem:corpus;DB_CLOSE_DELAY=-1", "sa", "")) {

            UserRepository.seed(connection);

            Server server = new Server(0);
            ServletContextHandler context = new ServletContextHandler();
            context.setContextPath("/");
            for (String path : CASES.keySet()) {
                context.addServlet(new ServletHolder(new CaseServlet(connection, path)), path);
            }
            server.setHandler(context);
            server.start();

            int port = ((ServerConnector) server.getConnectors()[0]).getLocalPort();
            for (Map.Entry<String, String[]> entry : CASES.entrySet()) {
                String path = entry.getKey();
                String payload = entry.getValue()[2];
                String body =
                        path.startsWith("/cookie/")
                                ? get(port, path, "name=" + payload)
                                : path.startsWith("/header/name-")
                                        ? getWithHeaderName(
                                                port, path + "?name=ignored", payload)
                                : path.startsWith("/parameter/name-")
                                        ? getWithParameterName(port, path, payload)
                                : path.startsWith("/body/")
                                        ? post(port, path, payload)
                                        : get(port, path + "?name=" + payload, null);
                System.out.println(
                        "CASE " + entry.getKey() + " " + entry.getValue()[0] + " -> " + body);
            }

            server.stop();

            dev.aegis.agent.AgentRuntime runtime = dev.aegis.agent.AgentRuntime.get();
            System.out.println("AGENT_PRESENT=" + (runtime != null));
            if (runtime != null) {
                System.out.println("SINKS_EVALUATED=" + runtime.sinksEvaluated());
                System.out.println("FINDINGS=" + runtime.findingsReported());
                System.out.println("HOOK_FAILURES=" + runtime.hookFailures());
            }
        }
        Thread.sleep(1_500);
    }

    /** For {@code /body/*} cases: the payload arrives as the raw request body, not a parameter. */
    private static String post(int port, String path, String body) throws Exception {
        HttpRequest request =
                HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build();
        HttpResponse<String> response =
                HttpClient.newBuilder()
                        .build()
                        .send(request, HttpResponse.BodyHandlers.ofString());
        return response.statusCode() + ":" + response.body().trim();
    }

    private static String get(int port, String path, String cookie) throws Exception {
        HttpRequest.Builder builder =
                HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).GET();
        if (cookie != null) {
            builder.header("Cookie", cookie);
        }
        HttpResponse<String> response =
                HttpClient.newBuilder()
                        // Never follow the open redirect. The point is that it was issued, not
                        // that some other host answered it.
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .build()
                        .send(builder.build(), HttpResponse.BodyHandlers.ofString());
        return response.statusCode() + ":" + response.body().trim();
    }

    private static String getWithHeaderName(int port, String path, String headerName)
            throws Exception {
        HttpRequest request =
                HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                        .header(headerName, "present")
                        .GET()
                        .build();
        HttpResponse<String> response =
                HttpClient.newBuilder()
                        .build()
                        .send(request, HttpResponse.BodyHandlers.ofString());
        return response.statusCode() + ":" + response.body().trim();
    }

    private static String getWithParameterName(int port, String path, String parameterName)
            throws Exception {
        String encodedName = URLEncoder.encode(parameterName, StandardCharsets.UTF_8);
        HttpRequest request =
                HttpRequest.newBuilder(
                                URI.create(
                                        "http://127.0.0.1:"
                                                + port
                                                + path
                                                + "?"
                                                + encodedName
                                                + "=selected"))
                        .GET()
                        .build();
        HttpResponse<String> response =
                HttpClient.newBuilder()
                        .build()
                        .send(request, HttpResponse.BodyHandlers.ofString());
        return response.statusCode() + ":" + response.body().trim();
    }

    /**
     * Dispatches to the case named by its own mapped path.
     *
     * <p>Every case writes through {@code getWriter()}, including the ones with nothing to do
     * with XSS. Mixing that with {@code getOutputStream()} on one response is illegal, and a
     * corpus whose safe cases take a different code path to its vulnerable ones is not measuring
     * what it claims to.
     */
    static final class CaseServlet extends HttpServlet {

        private static final String DOCUMENT =
                "<users><user name='alice' role='user'/><user name='root' role='admin'/></users>";

        private final Connection connection;
        private final String path;

        CaseServlet(Connection connection, String path) {
            this.connection = connection;
            this.path = path;
        }

        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response)
                throws IOException {
            String name = request.getParameter("name");
            PrintWriter out = response.getWriter();
            try {
                out.print(run(name, request, response));
            } catch (Exception e) {
                out.print("handled:" + e.getClass().getSimpleName());
            }
        }

        /** {@code /body/*} cases only: the payload is the raw request body, not a parameter. */
        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response)
                throws IOException {
            String name = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            PrintWriter out = response.getWriter();
            try {
                out.print(run(name, request, response));
            } catch (Exception e) {
                out.print("handled:" + e.getClass().getSimpleName());
            }
        }

        private String run(String name, HttpServletRequest request, HttpServletResponse response)
                throws Exception {
            return switch (path) {
                case "/sql/builder" -> sqlBuilder(name);
                case "/sql/plus" -> sqlPlus(name);
                case "/sql/concat" -> sqlConcat(name);
                case "/sql/substring" -> sqlSubstring(name);
                case "/sql/builder-replace" -> sqlBuilderReplace(name);
                case "/sql/builder-reverse" -> sqlBuilderReverse(name);
                case "/sql/format" -> sqlFormat(name);
                case "/sql/formatted" -> sqlFormatted(name);
                case "/sql/confirmed" -> sqlPlus(name);
                case "/sql/builder-replace-clears" -> sqlBuilderReplaceClears(name);
                case "/sql/builder-reverse-constant" -> sqlBuilderReverseConstant(name);
                case "/sql/format-constant" -> sqlFormatConstant(name);
                case "/sql/formatted-constant" -> sqlFormattedConstant(name);
                case "/sql/confirmed-constant" -> sqlConstant(name);
                case "/sql/prepared" -> sqlPrepared(name);
                case "/sql/constant" -> sqlConstant(name);
                case "/sql/identity" -> sqlIdentity(name);
                case "/cmd/exec" -> commandWithInput(name);
                case "/cmd/constant" -> commandConstant(name);
                case "/path/file" -> fileWithInput(name);
                case "/path/constant" -> fileConstant(name);
                case "/path/file-child" -> fileWithChildInput(name);
                case "/path/file-child-constant" -> fileWithChildConstant(name);
                case "/xss/write" -> xssReflected(name, response);
                case "/xss/escaped" -> xssEscaped(name, response);
                case "/xss/request-uri" -> xssRequestUri(request, response);
                case "/redirect/open" -> redirectOpen(name, response);
                case "/redirect/encoded" -> redirectEncoded(name, response);
                case "/header/set" -> headerFromInput(name, response);
                case "/header/constant" -> headerConstant(name, response);
                case "/header/name-to-sql" -> headerNameToSql(request);
                case "/header/name-constant" -> headerNameConstant(request);
                case "/parameter/name-to-sql" -> parameterNameToSql(request);
                case "/parameter/name-constant" -> parameterNameConstant(request);
                case "/ssrf/url" -> ssrfFromInput(name);
                case "/ssrf/constant" -> ssrfConstant(name);
                case "/ldap/search" -> ldapFromInput(name);
                case "/ldap/constant" -> ldapConstant(name);
                case "/xpath/evaluate" -> xpathFromInput(name);
                case "/xpath/constant" -> xpathConstant(name);
                case "/log/write" -> logFromInput(name);
                case "/log/constant" -> logConstant(name);
                case "/deser/read" -> deserializeFromInput(name);
                case "/deser/constant" -> deserializeConstant(name);
                case "/deser/base64" -> deserializeFromBase64(name);
                case "/deser/base64-constant" -> deserializeFromBase64Constant(name);
                case "/xxe/documentbuilder" -> xxeDocumentBuilder(name);
                case "/xxe/documentbuilder-constant" -> xxeDocumentBuilderConstant(name);
                case "/xxe/stax" -> xxeStax(name);
                case "/xxe/stax-constant" -> xxeStaxConstant(name);
                // Same sink logic as /sql/plus and /sql/constant — only the source differs.
                case "/body/sql" -> sqlPlus(name);
                case "/body/sql-constant" -> sqlConstant(name);
                case "/split/first" -> splitInjection(name);
                case "/split/constant" -> splitConstant(name);
                case "/cookie/sql" -> cookieInjection(request);
                case "/cookie/decoded" -> cookieDecoded(request);
                case "/cookie/constant" -> cookieConstant(request);
                case "/noop" -> "seen:" + name.length();
                default -> throw new IllegalStateException("unmapped case " + path);
            };
        }

        // --- SQL ----------------------------------------------------------------------

        /** The textbook defect: a request parameter accumulated into a StringBuilder. */
        private String sqlBuilder(String name) throws Exception {
            StringBuilder sql = new StringBuilder("SELECT name FROM users WHERE name = '");
            sql.append(name).append("'");
            return query(sql.toString());
        }

        /**
         * The same defect written with {@code +}.
         *
         * <p>The most common shape of SQL injection in Java, and the one an agent is most likely
         * to miss: since Java 9 the compiler lowers this to an {@code invokedynamic} against
         * {@code StringConcatFactory} rather than to {@code StringBuilder}.
         */
        private String sqlPlus(String name) throws Exception {
            return query("SELECT name FROM users WHERE name = '" + name + "'");
        }

        private String sqlConcat(String name) throws Exception {
            return query("SELECT name FROM users WHERE name = '".concat(name).concat("'"));
        }

        /** Only part of the parameter reaches the sink; the offsets must still be right. */
        private String sqlSubstring(String name) throws Exception {
            StringBuilder sql = new StringBuilder("SELECT name FROM users WHERE name = '''");
            sql.append(name.substring(1)).append("'");
            return query(sql.toString());
        }

        /** The OWASP Benchmark shape that substitutes a parameter into an existing builder. */
        private String sqlBuilderReplace(String name) throws Exception {
            String prefix = "SELECT name FROM users WHERE name = '";
            String placeholder = "placeholder";
            StringBuilder sql = new StringBuilder(prefix).append(placeholder).append("'");
            sql.replace(prefix.length(), prefix.length() + placeholder.length(), name);
            return query(sql.toString());
        }

        /** Reversal must move the range, not detach the parameter from its provenance. */
        private String sqlBuilderReverse(String name) throws Exception {
            StringBuilder value = new StringBuilder().append(name).reverse().reverse();
            StringBuilder sql = new StringBuilder("SELECT name FROM users WHERE name = '");
            sql.append(value).append("'");
            return query(sql.toString());
        }

        private String sqlFormat(String name) throws Exception {
            return query(String.format("SELECT name FROM users WHERE name = '%s'", name));
        }

        private String sqlFormatted(String name) throws Exception {
            return query("SELECT name FROM users WHERE name = '%s'".formatted(name));
        }

        /** Removing the only tainted range must remove the builder's side-table entry too. */
        private String sqlBuilderReplaceClears(String name) throws Exception {
            String prefix = "SELECT name FROM users WHERE name = '";
            StringBuilder sql = new StringBuilder(prefix).append(name).append("'");
            sql.replace(prefix.length(), prefix.length() + name.length(), "alice");
            return query(sql.toString());
        }

        private String sqlBuilderReverseConstant(String name) throws Exception {
            StringBuilder value = new StringBuilder("alice").reverse().reverse();
            return query("SELECT name FROM users WHERE name = '" + value + "'")
                    + ":"
                    + name.length();
        }

        private String sqlFormatConstant(String name) throws Exception {
            return query(String.format("SELECT name FROM users WHERE name = '%s'", "alice"))
                    + ":"
                    + name.length();
        }

        private String sqlFormattedConstant(String name) throws Exception {
            return query("SELECT name FROM users WHERE name = '%s'".formatted("alice"))
                    + ":"
                    + name.length();
        }

        private String sqlPrepared(String name) throws Exception {
            try (PreparedStatement statement =
                    connection.prepareStatement("SELECT name FROM users WHERE name = ?")) {
                statement.setString(1, name);
                try (ResultSet rows = statement.executeQuery()) {
                    int count = 0;
                    while (rows.next()) {
                        count++;
                    }
                    return "rows:" + count;
                }
            }
        }

        /** Reads the parameter, then queries something that has nothing to do with it. */
        private String sqlConstant(String name) throws Exception {
            return query("SELECT name FROM users WHERE id = 1") + ":" + name.length();
        }

        /**
         * The parameter's <em>value</em> also appears in the query, as a constant.
         *
         * <p>Taint is tracked by object identity, not by content. An engine that keyed on
         * equality would report this, and would then report every query containing a common word
         * a user happened to type.
         */
        private String sqlIdentity(String name) throws Exception {
            String constant = "alice";
            return query("SELECT name FROM users WHERE name = '" + constant + "'")
                    + ":"
                    + name.length();
        }

        /**
         * The Benchmark's split shape: one parameter carved into pieces, one piece concatenated.
         *
         * <p>Splitting removes the delimiters, so no piece keeps the offsets it had in the
         * original. The taint has to survive as provenance even though the positions cannot.
         */
        private String splitInjection(String name) throws Exception {
            String piece = (name + ",unused").split(",")[0];
            StringBuilder sql = new StringBuilder("SELECT name FROM users WHERE name = '");
            sql.append(piece).append("'");
            return query(sql.toString());
        }

        private String splitConstant(String name) throws Exception {
            String piece = "alice,bob".split(",")[0];
            return query("SELECT name FROM users WHERE name = '" + piece + "'")
                    + ":"
                    + name.length();
        }

        // --- cookie ---------------------------------------------------------------------

        /**
         * A cookie concatenated into SQL.
         *
         * <p>Cookies are the source developers forget is attacker-controlled, because the
         * server set them. Nothing stops the client sending back whatever it likes.
         */
        private String cookieInjection(HttpServletRequest request) throws Exception {
            String value = cookie(request, "name");
            StringBuilder sql = new StringBuilder("SELECT name FROM users WHERE name = '");
            sql.append(value).append("'");
            return query(sql.toString());
        }

        /**
         * The OWASP Benchmark's exact cookie shape: read, URL-decode, concatenate.
         *
         * <p>The only difference between this and {@link #cookieInjection}, which the agent
         * detects, is the decode step — so if the Benchmark's 60 cookie cases fail and this
         * one does too, the decode is where the chain breaks.
         */
        private String cookieDecoded(HttpServletRequest request) throws Exception {
            String value = URLDecoder.decode(cookie(request, "name"), StandardCharsets.UTF_8);
            StringBuilder sql = new StringBuilder("SELECT name FROM users WHERE name = '");
            sql.append(value).append("'");
            return query(sql.toString());
        }

        private String cookieConstant(HttpServletRequest request) throws Exception {
            return query("SELECT name FROM users WHERE name = 'alice'")
                    + ":"
                    + cookie(request, "name").length();
        }

        private static String cookie(HttpServletRequest request, String wanted) {
            jakarta.servlet.http.Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (jakarta.servlet.http.Cookie candidate : cookies) {
                    if (wanted.equals(candidate.getName())) {
                        return candidate.getValue();
                    }
                }
            }
            return "";
        }

        private String query(String sql) throws Exception {
            try (Statement statement = connection.createStatement();
                    ResultSet rows = statement.executeQuery(sql)) {
                int count = 0;
                while (rows.next()) {
                    count++;
                }
                return "rows:" + count;
            }
        }

        // --- command ------------------------------------------------------------------

        private String commandWithInput(String name) {
            try {
                // Deliberately a binary that does not exist: the sink hook fires on entry, so
                // the finding is reported without this test ever running anything.
                Runtime.getRuntime().exec("aegis-corpus-nonexistent " + name);
                return "executed";
            } catch (IOException e) {
                return "handled:IOException";
            }
        }

        private String commandConstant(String name) {
            try {
                Runtime.getRuntime().exec("aegis-corpus-nonexistent --version");
                return "executed:" + name.length();
            } catch (IOException e) {
                return "handled:IOException";
            }
        }

        // --- path ---------------------------------------------------------------------

        private String fileWithInput(String name) {
            return "exists:" + new java.io.File("corpus-data/" + name).exists();
        }

        private String fileConstant(String name) {
            return "exists:"
                    + new java.io.File("corpus-data/fixed.txt").exists()
                    + ":"
                    + name.length();
        }

        private String fileWithChildInput(String name) {
            java.io.File base = new java.io.File("corpus-data");
            return "exists:" + new java.io.File(base, name).exists();
        }

        private String fileWithChildConstant(String name) {
            java.io.File base = new java.io.File("corpus-data");
            return "exists:" + new java.io.File(base, "fixed.txt").exists() + ":" + name.length();
        }

        // --- reflected XSS ------------------------------------------------------------

        private String xssReflected(String name, HttpServletResponse response) throws IOException {
            response.getWriter().print("<p>" + name + "</p>");
            return "";
        }

        /** The same page, escaped. The escaper clears XSS and nothing else. */
        private String xssEscaped(String name, HttpServletResponse response) throws IOException {
            response.getWriter().print("<p>" + StringEscapeUtils.escapeHtml4(name) + "</p>");
            return "";
        }

        /**
         * Unescaped, unsanitised, and still expected to produce nothing: this is what Thymeleaf
         * does internally to resolve its own template-declared resource links, and it must not
         * read as reflected XSS just because the value nominally came off the request.
         */
        private String xssRequestUri(HttpServletRequest request, HttpServletResponse response)
                throws IOException {
            response.getWriter().print("<link href='" + request.getRequestURI() + "'>");
            return "";
        }

        // --- open redirect and header injection ---------------------------------------

        private String redirectOpen(String name, HttpServletResponse response) throws IOException {
            response.sendRedirect(name);
            return "";
        }

        /**
         * Percent-encoded, so the value cannot escape the query parameter it sits in.
         *
         * <p>URL encoding clears the URL-context rules only. The same call would do nothing to
         * make this value safe in HTML or in SQL, which is why sanitization is tracked per rule
         * class rather than as one flag.
         */
        private String redirectEncoded(String name, HttpServletResponse response)
                throws IOException {
            response.sendRedirect("/next?to=" + URLEncoder.encode(name, StandardCharsets.UTF_8));
            return "";
        }

        private String headerFromInput(String name, HttpServletResponse response) {
            response.setHeader("X-Echo", name);
            return "set";
        }

        private String headerConstant(String name, HttpServletResponse response) {
            response.setHeader("X-Echo", "constant");
            return "set:" + name.length();
        }

        private String headerNameToSql(HttpServletRequest request) throws Exception {
            String selected = "missing";
            java.util.Enumeration<String> names = request.getHeaderNames();
            while (names.hasMoreElements()) {
                String candidate = names.nextElement();
                if (candidate.equalsIgnoreCase("X-Aegis-Probe")) {
                    selected = candidate;
                }
            }
            return query("SELECT name FROM users WHERE name = '" + selected + "'");
        }

        private String headerNameConstant(HttpServletRequest request) throws Exception {
            int seen = 0;
            java.util.Enumeration<String> names = request.getHeaderNames();
            while (names.hasMoreElements()) {
                names.nextElement();
                seen++;
            }
            return query("SELECT name FROM users WHERE id = 1") + ":" + seen;
        }

        private String parameterNameToSql(HttpServletRequest request) throws Exception {
            String selected = "missing";
            java.util.Enumeration<String> names = request.getParameterNames();
            while (names.hasMoreElements()) {
                String candidate = names.nextElement();
                String[] values = request.getParameterValues(candidate);
                if (values != null && values.length > 0 && values[0].equals("selected")) {
                    selected = candidate;
                }
            }
            return query("SELECT name FROM users WHERE name = '" + selected + "'");
        }

        private String parameterNameConstant(HttpServletRequest request) throws Exception {
            int seen = 0;
            java.util.Enumeration<String> names = request.getParameterNames();
            while (names.hasMoreElements()) {
                names.nextElement();
                seen++;
            }
            return query("SELECT name FROM users WHERE id = 1") + ":" + seen;
        }

        // --- SSRF ---------------------------------------------------------------------

        private String ssrfFromInput(String name) throws Exception {
            // Constructed, never opened. The defect is letting an attacker choose the
            // destination; whether this process then dials it is the attacker's decision.
            //
            // The host is deliberately *not* echoed back. An earlier version returned it, and
            // the agent correctly reported a second finding — reflected XSS — which is a fine
            // result for the product and a bad one for a corpus that is supposed to isolate one
            // defect per case.
            URL target = new URL("http://" + name + "/status");
            return "url:" + target.getProtocol();
        }

        private String ssrfConstant(String name) throws Exception {
            return "url:" + new URL("http://127.0.0.1/status").getHost() + ":" + name.length();
        }

        // --- LDAP ---------------------------------------------------------------------

        /**
         * The filter is the injection point, not the distinguished name.
         *
         * <p>No directory is running, and none is needed: the hook fires on entry, before the
         * context tries to reach one.
         */
        private String ldapFromInput(String name) {
            try {
                new InitialDirContext(new Hashtable<>())
                        .search("ou=users", "(uid=" + name + ")", null);
                return "searched";
            } catch (Exception e) {
                return "handled:" + e.getClass().getSimpleName();
            }
        }

        private String ldapConstant(String name) {
            try {
                new InitialDirContext(new Hashtable<>()).search("ou=users", "(uid=fixed)", null);
                return "searched:" + name.length();
            } catch (Exception e) {
                return "handled:" + e.getClass().getSimpleName() + ":" + name.length();
            }
        }

        // --- XPath --------------------------------------------------------------------

        private String xpathFromInput(String name) throws Exception {
            String expression = "/users/user[@name='" + name + "']/@role";
            return "role:"
                    + XPathFactory.newInstance()
                            .newXPath()
                            .evaluate(expression, new InputSource(new StringReader(DOCUMENT)));
        }

        private String xpathConstant(String name) throws Exception {
            return "role:"
                    + XPathFactory.newInstance()
                            .newXPath()
                            .evaluate(
                                    "/users/user[@name='alice']/@role",
                                    new InputSource(new StringReader(DOCUMENT)))
                    + ":"
                    + name.length();
        }

        // --- log injection ------------------------------------------------------------

        /** A newline in an audit log is how an attacker writes history rather than appears in it. */
        private String logFromInput(String name) {
            LOG.info("login attempt for " + name);
            return "logged";
        }

        private String logConstant(String name) {
            LOG.info("login attempt");
            return "logged:" + name.length();
        }

        // --- unsafe deserialization ---------------------------------------------------

        /**
         * The chain that makes this the hardest sink to see.
         *
         * <p>The taint arrives as text, becomes bytes, becomes a stream, and only then reaches
         * Java serialization. Nothing after the first step is a string, so a taint table that
         * only ever holds character data cannot follow it.
         */
        private String deserializeFromInput(String name) {
            byte[] payload = name.getBytes(StandardCharsets.UTF_8);
            try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(payload))) {
                return "read:" + in.readObject();
            } catch (Exception e) {
                return "handled:" + e.getClass().getSimpleName();
            }
        }

        private String deserializeConstant(String name) {
            byte[] fixed = "fixed-payload".getBytes(StandardCharsets.UTF_8);
            try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(fixed))) {
                return "read:" + in.readObject();
            } catch (Exception e) {
                return "handled:" + e.getClass().getSimpleName() + ":" + name.length();
            }
        }

        private String deserializeFromBase64(String name) {
            byte[] payload = java.util.Base64.getDecoder().decode(name);
            try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(payload))) {
                return "read:" + in.readObject();
            } catch (Exception e) {
                return "handled:" + e.getClass().getSimpleName();
            }
        }

        private String deserializeFromBase64Constant(String name) {
            byte[] fixed =
                    java.util.Base64.getDecoder()
                            .decode(
                                    java.util.Base64.getEncoder()
                                            .encodeToString(
                                                    "fixed-payload"
                                                            .getBytes(StandardCharsets.UTF_8)));
            try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(fixed))) {
                return "read:" + in.readObject();
            } catch (Exception e) {
                return "handled:" + e.getClass().getSimpleName() + ":" + name.length();
            }
        }

        // --- XML External Entity injection ---------------------------------------------

        private String xxeDocumentBuilder(String name) {
            try {
                DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
                var document =
                        builder.parse(new ByteArrayInputStream(name.getBytes(StandardCharsets.UTF_8)));
                return "root:" + document.getDocumentElement().getNodeName();
            } catch (Exception e) {
                return "handled:" + e.getClass().getSimpleName();
            }
        }

        private String xxeDocumentBuilderConstant(String name) {
            try {
                DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
                var document =
                        builder.parse(
                                new ByteArrayInputStream("<x/>".getBytes(StandardCharsets.UTF_8)));
                return "root:" + document.getDocumentElement().getNodeName() + ":" + name.length();
            } catch (Exception e) {
                return "handled:" + e.getClass().getSimpleName() + ":" + name.length();
            }
        }

        private String xxeStax(String name) {
            try {
                XMLStreamReader reader =
                        XMLInputFactory.newInstance().createXMLStreamReader(new StringReader(name));
                int event = reader.next();
                return "event:" + event;
            } catch (Exception e) {
                return "handled:" + e.getClass().getSimpleName();
            }
        }

        private String xxeStaxConstant(String name) {
            try {
                XMLStreamReader reader =
                        XMLInputFactory.newInstance()
                                .createXMLStreamReader(new StringReader("<x/>"));
                int event = reader.next();
                return "event:" + event + ":" + name.length();
            } catch (Exception e) {
                return "handled:" + e.getClass().getSimpleName() + ":" + name.length();
            }
        }
    }
}
