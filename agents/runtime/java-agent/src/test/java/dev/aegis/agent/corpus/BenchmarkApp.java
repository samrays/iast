package dev.aegis.agent.corpus;

import dev.aegis.agent.demo.UserRepository;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.Map;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

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

    /** Path → expected verdict and, when vulnerable, the rule that must fire. */
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
                String body = get(port, path + "?name=" + payload);
                System.out.println("CASE " + path + " " + entry.getValue()[0] + " -> " + body);
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

    private static String get(int port, String path) throws Exception {
        HttpResponse<String> response =
                HttpClient.newHttpClient()
                        .send(
                                HttpRequest.newBuilder(
                                                URI.create("http://127.0.0.1:" + port + path))
                                        .GET()
                                        .build(),
                                HttpResponse.BodyHandlers.ofString());
        return response.body().trim();
    }

    /** Dispatches to the case named by its own mapped path. */
    static final class CaseServlet extends HttpServlet {

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
            String result;
            try {
                result = run(name);
            } catch (Exception e) {
                result = "handled:" + e.getClass().getSimpleName();
            }
            response.setContentType("text/plain; charset=utf-8");
            response.getOutputStream().write(result.getBytes(StandardCharsets.UTF_8));
        }

        private String run(String name) throws Exception {
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
         * <p>The most common shape of SQL injection in Java, and the one an agent is most
         * likely to miss: since Java 9 the compiler lowers this to an {@code invokedynamic}
         * against {@code StringConcatFactory} rather than to {@code StringBuilder}, so an
         * agent that only instruments the builder finds nothing here.
         */
        private String sqlPlus(String name) throws Exception {
            return query("SELECT name FROM users WHERE name = '" + name + "'");
        }

        private String sqlConcat(String name) throws Exception {
            String sql = "SELECT name FROM users WHERE name = '".concat(name).concat("'");
            return query(sql);
        }

        /** Only part of the parameter reaches the sink; the offsets must still be right. */
        private String sqlSubstring(String name) throws Exception {
            String trimmed = name.substring(1);
            StringBuilder sql = new StringBuilder("SELECT name FROM users WHERE name = '''");
            sql.append(trimmed).append("'");
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
            int ignored = name.length();
            return query("SELECT name FROM users WHERE id = 1") + ":" + ignored;
        }

        /**
         * The parameter's <em>value</em> also appears in the query, as a constant.
         *
         * <p>Taint is tracked by object identity, not by content. An engine that keyed on
         * equality would report this, and would then report every query containing a common
         * word a user happened to type.
         */
        private String sqlIdentity(String name) throws Exception {
            String constant = "alice";
            return query("SELECT name FROM users WHERE name = '" + constant + "'")
                    + ":"
                    + name.length();
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
            File target = new File("corpus-data/" + name);
            return "exists:" + target.exists();
        }

        private String fileConstant(String name) {
            File target = new File("corpus-data/fixed.txt");
            return "exists:" + target.exists() + ":" + name.length();
        }
    }
}
