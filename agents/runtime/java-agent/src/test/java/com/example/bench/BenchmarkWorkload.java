package com.example.bench;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

/**
 * The workload the overhead measurement runs, with and without the agent.
 *
 * <p>Shaped like request handling rather than like a microbenchmark: real HTTP on a loopback
 * socket, a servlet container, parameters read through the servlet API, string assembly, and a
 * parameterised query against a real database. Instrumentation touches every one of those, so
 * the agent has nowhere to hide.
 *
 * <p>It is deliberately <em>lighter</em> on business logic than a real application, which makes
 * the measurement conservative: the same absolute agent cost is a larger fraction of a smaller
 * request. A number that looks acceptable here will look better in production, not worse.
 *
 * <p>The endpoint is written correctly and produces no findings, so what is measured is the
 * steady-state cost of tracking — not the cost of reporting, which only a vulnerable
 * application pays.
 */
public final class BenchmarkWorkload {

    private static final String[] NAMES = {"alice", "bob", "carol"};

    public static void main(String[] args) throws Exception {
        int warmup = Integer.parseInt(System.getProperty("aegis.bench.warmup", "3000"));
        int measured = Integer.parseInt(System.getProperty("aegis.bench.requests", "6000"));
        int rounds = Integer.parseInt(System.getProperty("aegis.bench.rounds", "5"));

        Class.forName("org.h2.Driver");
        try (Connection connection =
                DriverManager.getConnection("jdbc:h2:mem:bench;DB_CLOSE_DELAY=-1", "sa", "")) {

            try (Statement setup = connection.createStatement()) {
                setup.execute("CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(64))");
                setup.execute("INSERT INTO users VALUES (1, 'alice'), (2, 'bob'), (3, 'carol')");
            }

            Server server = new Server(0);
            ServletContextHandler context = new ServletContextHandler();
            context.setContextPath("/");
            context.addServlet(new ServletHolder(new WorkloadServlet(connection)), "/lookup");
            server.setHandler(context);
            server.start();

            int port = ((ServerConnector) server.getConnectors()[0]).getLocalPort();
            HttpClient client = HttpClient.newHttpClient();
            String base = "http://127.0.0.1:" + port + "/lookup?name=";

            // Warm up until the JIT has compiled both the application and the inlined advice.
            // Measuring interpreted bytecode would overstate the agent's cost several times over.
            drive(client, base, warmup);

            List<Long> perRound = new ArrayList<>();
            for (int round = 0; round < rounds; round++) {
                long start = System.nanoTime();
                drive(client, base, measured);
                perRound.add((System.nanoTime() - start) / measured);
            }
            Collections.sort(perRound);

            server.stop();

            // The minimum, not the mean.
            //
            // Two other metrics were tried and discarded. Whole-process CPU time is dominated
            // by the JIT and collector threads and moved ±70% between identical runs.
            // Per-thread CPU time is quantised to the scheduler tick — 15.6ms on Windows —
            // which for a request measured in microseconds reports either zero or one tick.
            // Wall time works, provided the estimator ignores interference: noise only ever
            // makes a round slower, so the fastest round is the closest available reading of
            // what the code itself costs.
            System.out.println("NS_PER_REQUEST=" + perRound.get(0));
            System.out.println("MEDIAN_NS_PER_REQUEST=" + median(perRound));
            System.out.println("ROUNDS=" + perRound);
            System.out.println("AGENT_PRESENT=" + (dev.aegis.agent.AgentRuntime.get() != null));
        }
    }

    private static long median(List<Long> sorted) {
        return sorted.get(sorted.size() / 2);
    }

    private static void drive(HttpClient client, String base, int requests) throws Exception {
        for (int index = 0; index < requests; index++) {
            HttpRequest request =
                    HttpRequest.newBuilder(URI.create(base + NAMES[index % NAMES.length]))
                            .GET()
                            .build();
            client.send(request, HttpResponse.BodyHandlers.discarding());
        }
    }

    /** Correctly written request handling: parameters read, strings assembled, query bound. */
    static final class WorkloadServlet extends HttpServlet {

        private final Connection connection;

        WorkloadServlet(Connection connection) {
            this.connection = connection;
        }

        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response)
                throws IOException {
            String name = request.getParameter("name");
            String agent = request.getHeader("User-Agent");

            // The string work a request handler actually does: a cache key, a log line, a
            // label. All three propagation paths the agent instruments.
            String cacheKey = "user:" + name + ":" + (agent == null ? "" : agent.length());
            StringBuilder audit = new StringBuilder(64);
            audit.append("lookup ").append(name).append(" via ").append(cacheKey.length());
            String normalized = name.trim().toLowerCase();

            try (PreparedStatement statement =
                    connection.prepareStatement("SELECT id FROM users WHERE name = ?")) {
                statement.setString(1, normalized);
                try (ResultSet rows = statement.executeQuery()) {
                    int id = rows.next() ? rows.getInt(1) : -1;
                    byte[] body =
                            (audit.length() + ":" + id).getBytes(StandardCharsets.UTF_8);
                    response.setContentType("text/plain; charset=utf-8");
                    response.getOutputStream().write(body);
                }
            } catch (Exception e) {
                response.setStatus(500);
            }
        }
    }
}
