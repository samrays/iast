package dev.aegis.agent.demo;

import dev.aegis.agent.AgentRuntime;
import dev.aegis.agent.runtime.RequestContext;
import dev.aegis.agent.taint.SourceKind;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * A deliberately vulnerable application, run in a separate JVM under {@code -javaagent}.
 *
 * <p>Nothing in {@link UserRepository} knows the agent exists. It is ordinary, careless
 * Java — a {@code StringBuilder} and a plain {@code Statement} — which is exactly the shape
 * of the code this product is sold to find.
 */
public final class VulnerableApp {

    public static void main(String[] args) throws Exception {
        try (Connection connection =
                DriverManager.getConnection("jdbc:h2:mem:demo;DB_CLOSE_DELAY=-1", "sa", "")) {

            try (Statement setup = connection.createStatement()) {
                setup.execute("CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(64))");
                setup.execute("INSERT INTO users VALUES (1, 'alice'), (2, 'bob'), (3, 'carol')");
            }

            UserRepository repository = new UserRepository(connection);

            // --- request 1: an actual SQL injection ------------------------------------
            RequestContext.begin("demo-trace-1", true)
                    .withHttp("GET", "/users/search", "203.0.113.7");
            String malicious = new String("' OR 1=1--");
            AgentRuntime.onSource(malicious, SourceKind.PARAMETER, "name");

            List<String> injected = repository.findByNameUnsafe(malicious);
            System.out.println("UNSAFE_ROWS=" + injected.size());
            RequestContext.end();

            // --- request 2: the same query, bound ---------------------------------------
            RequestContext.begin("demo-trace-2", true)
                    .withHttp("GET", "/users/search", "203.0.113.7");
            String alsoMalicious = new String("' OR 1=1--");
            AgentRuntime.onSource(alsoMalicious, SourceKind.PARAMETER, "name");

            List<String> bound = repository.findByNameSafe(alsoMalicious);
            System.out.println("SAFE_ROWS=" + bound.size());
            RequestContext.end();

            // --- request 3: the vulnerable path with an internal constant ---------------
            RequestContext.begin("demo-trace-3", true).withHttp("GET", "/users/search", "10.0.0.1");
            List<String> clean = repository.findByNameUnsafe("alice");
            System.out.println("CLEAN_ROWS=" + clean.size());
            RequestContext.end();

            AgentRuntime runtime = AgentRuntime.get();
            System.out.println("AGENT_PRESENT=" + (runtime != null));
            if (runtime != null) {
                System.out.println("SINKS_EVALUATED=" + runtime.sinksEvaluated());
                System.out.println("FINDINGS=" + runtime.findingsReported());
                System.out.println("HOOK_FAILURES=" + runtime.hookFailures());
            }
        }
        // Give the reporting thread a moment; the shutdown hook flushes whatever remains.
        Thread.sleep(1_500);
    }

    /** Ordinary application code, written the way vulnerable code is actually written. */
    static final class UserRepository {
        private final Connection connection;

        UserRepository(Connection connection) {
            this.connection = connection;
        }

        List<String> findByNameUnsafe(String name) throws SQLException {
            StringBuilder sql = new StringBuilder();
            sql.append("SELECT name FROM users WHERE name = '");
            sql.append(name);
            sql.append("'");

            List<String> results = new ArrayList<>();
            try (Statement statement = connection.createStatement();
                    ResultSet rows = statement.executeQuery(sql.toString())) {
                while (rows.next()) {
                    results.add(rows.getString(1));
                }
            }
            return results;
        }

        List<String> findByNameSafe(String name) throws SQLException {
            List<String> results = new ArrayList<>();
            try (PreparedStatement statement =
                    connection.prepareStatement("SELECT name FROM users WHERE name = ?")) {
                statement.setString(1, name);
                try (ResultSet rows = statement.executeQuery()) {
                    while (rows.next()) {
                        results.add(rows.getString(1));
                    }
                }
            }
            return results;
        }
    }
}
