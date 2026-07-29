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

    /** Path → expected verdict, the rule that must fire, and the payload to send. */
    public static final Map<String, String[]> CASES = new LinkedHashMap<>();

    static {
        // --- SQL injection ----------------------------------------------------------------
        register("/sql/builder", Expectation.VULNERABLE, "sql-injection", SQL_PAYLOAD);
        register("/sql/plus", Expectation.VULNERABLE, "sql-injection", SQL_PAYLOAD);
        register("/sql/concat", Expectation.VULNERABLE, "sql-injection", SQL_PAYLOAD);
        register("/sql/substring", Expectation.VULNERABLE, "sql-injection", SQL_PAYLOAD);
        register("/sql/prepared", Expectation.SAFE, "", SQL_PAYLOAD);
        register("/sql/constant", Expectation.SAFE, "", SQL_PAYLOAD);
        register("/sql/identity", Expectation.SAFE, "", "alice");

        // --- Command injection ------------------------------------------------------------
        register("/cmd/exec", Expectation.VULNERABLE, "command-injection", CMD_PAYLOAD);
        register("/cmd/constant", Expectation.SAFE, "", CMD_PAYLOAD);

        // --- Path traversal ---------------------------------------------------------------
        register("/path/file", Expectation.VULNERABLE, "path-traversal", PATH_PAYLOAD);
        register("/path/constant", Expectation.SAFE, "", PATH_PAYLOAD);

        // --- Reflected XSS ----------------------------------------------------------------
        register("/xss/write", Expectation.VULNERABLE, "reflected-xss", XSS_PAYLOAD);
        register("/xss/escaped", Expectation.SAFE, "", XSS_PAYLOAD);

        // --- Open redirect ----------------------------------------------------------------
        register("/redirect/open", Expectation.VULNERABLE, "open-redirect", REDIRECT_PAYLOAD);
        register("/redirect/encoded", Expectation.SAFE, "", REDIRECT_PAYLOAD);

        // --- Header injection -------------------------------------------------------------
        register("/header/set", Expectation.VULNERABLE, "header-injection", XSS_PAYLOAD);
        register("/header/constant", Expectation.SAFE, "", XSS_PAYLOAD);

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

        // --- Cookie as a source -----------------------------------------------------------
        register("/cookie/sql", Expectation.VULNERABLE, "sql-injection", SQL_PAYLOAD);
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

        private String run(String name, HttpServletRequest request, HttpServletResponse response)
                throws Exception {
            return switch (path) {
                case "/sql/builder" -> sqlBuilder(name);
                case "/sql/plus" -> sqlPlus(name);
                case "/sql/concat" -> sqlConcat(name);
                case "/sql/substring" -> sqlSubstring(name);
                case "/sql/prepared" -> sqlPrepared(name);
                case "/sql/constant" -> sqlConstant(name);
                case "/sql/identity" -> sqlIdentity(name);
                case "/cmd/exec" -> commandWithInput(name);
                case "/cmd/constant" -> commandConstant(name);
                case "/path/file" -> fileWithInput(name);
                case "/path/constant" -> fileConstant(name);
                case "/xss/write" -> xssReflected(name, response);
                case "/xss/escaped" -> xssEscaped(name, response);
                case "/redirect/open" -> redirectOpen(name, response);
                case "/redirect/encoded" -> redirectEncoded(name, response);
                case "/header/set" -> headerFromInput(name, response);
                case "/header/constant" -> headerConstant(name, response);
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
    }
}
