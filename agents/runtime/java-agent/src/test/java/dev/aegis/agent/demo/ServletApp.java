package dev.aegis.agent.demo;

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
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

/**
 * A deliberately vulnerable web application, served by a real servlet container.
 *
 * <p>Run in a separate JVM under {@code -javaagent}, this is the closest thing to a customer
 * deployment the suite can produce without a customer: Jetty accepts genuine HTTP on a real
 * socket, the request object is a container class the agent has never seen at compile time,
 * the parameter arrives through {@code getParameter} rather than a test helper, and the work
 * happens on a pooled container thread.
 *
 * <p>The application never mentions the agent. It does not open a request context, does not
 * declare a source, and does not know a taint engine exists — which is the entire claim being
 * tested.
 */
public final class ServletApp {

    /** Percent-encoded {@code ' OR 1=1--}. */
    private static final String PAYLOAD = "%27%20OR%201%3D1--";

    public static void main(String[] args) throws Exception {
        Class.forName("org.h2.Driver");
        try (Connection connection =
                DriverManager.getConnection("jdbc:h2:mem:web;DB_CLOSE_DELAY=-1", "sa", "")) {

            UserRepository.seed(connection);
            ExecutorService executor = Executors.newFixedThreadPool(2);
            UserRepository repository = new UserRepository(connection);

            Server server = new Server(0);
            ServletContextHandler context = new ServletContextHandler();
            context.setContextPath("/");
            context.addServlet(new ServletHolder(new SearchServlet(repository)), "/search");
            context.addServlet(new ServletHolder(new SafeServlet(repository)), "/safe");
            context.addServlet(
                    new ServletHolder(new AsyncSearchServlet(repository, executor)), "/async");
            context.addServlet(new ServletHolder(new EchoServlet()), "/echo");
            server.setHandler(context);
            server.start();

            int port = ((ServerConnector) server.getConnectors()[0]).getLocalPort();
            System.out.println("PORT=" + port);

            // Every call is real HTTP over the loopback interface, not a direct method call.
            System.out.println("SEARCH_ROWS=" + get(port, "/search?name=" + PAYLOAD));
            System.out.println("SAFE_ROWS=" + get(port, "/safe?name=" + PAYLOAD));
            System.out.println("ASYNC_ROWS=" + get(port, "/async?name=" + PAYLOAD));
            System.out.println("ECHO=" + get(port, "/echo?greeting=hello"));

            server.stop();
            executor.shutdownNow();

            dev.aegis.agent.AgentRuntime runtime = dev.aegis.agent.AgentRuntime.get();
            System.out.println("AGENT_PRESENT=" + (runtime != null));
            if (runtime != null) {
                System.out.println("SINKS_EVALUATED=" + runtime.sinksEvaluated());
                System.out.println("FINDINGS=" + runtime.findingsReported());
                System.out.println("HOOK_FAILURES=" + runtime.hookFailures());
            }
        }
        // The shutdown hook flushes whatever the reporting thread has not sent yet.
        Thread.sleep(1_500);
    }

    private static String get(int port, String path) throws Exception {
        HttpRequest request =
                HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                        .header("X-Aegis-Test", "true")
                        .GET()
                        .build();
        HttpResponse<String> response =
                HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        return response.body().trim();
    }

    /** The vulnerable endpoint: a request parameter concatenated into SQL. */
    static final class SearchServlet extends HttpServlet {
        private final UserRepository repository;

        SearchServlet(UserRepository repository) {
            this.repository = repository;
        }

        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response)
                throws IOException {
            String name = request.getParameter("name");
            try {
                List<String> rows = repository.findByNameUnsafe(name);
                write(response, String.valueOf(rows.size()));
            } catch (Exception e) {
                response.setStatus(500);
                write(response, "error: " + e.getMessage());
            }
        }
    }

    /** The same endpoint, written correctly. Must never produce a finding. */
    static final class SafeServlet extends HttpServlet {
        private final UserRepository repository;

        SafeServlet(UserRepository repository) {
            this.repository = repository;
        }

        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response)
                throws IOException {
            String name = request.getParameter("name");
            try {
                write(response, String.valueOf(repository.findByNameSafe(name).size()));
            } catch (Exception e) {
                response.setStatus(500);
                write(response, "error: " + e.getMessage());
            }
        }
    }

    /**
     * The vulnerable query again, executed on a different thread.
     *
     * <p>This is the case that separates a real IAST agent from a demo: the parameter is read
     * on the container's thread and reaches the sink on a pool thread, so a taint table scoped
     * to a {@code ThreadLocal} and nothing else would report nothing at all.
     */
    static final class AsyncSearchServlet extends HttpServlet {
        private final UserRepository repository;
        private final ExecutorService executor;

        AsyncSearchServlet(UserRepository repository, ExecutorService executor) {
            this.repository = repository;
            this.executor = executor;
        }

        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response)
                throws IOException {
            String name = request.getParameter("name");
            try {
                List<String> rows = executor.submit(() -> repository.findByNameUnsafe(name)).get();
                write(response, String.valueOf(rows.size()));
            } catch (Exception e) {
                response.setStatus(500);
                write(response, "error: " + e.getMessage());
            }
        }
    }

    /** Harmless: reads a parameter and reaches no sink. Its route must still be discovered. */
    static final class EchoServlet extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response)
                throws IOException {
            write(response, String.valueOf(request.getParameter("greeting")));
        }
    }

    private static void write(HttpServletResponse response, String body) throws IOException {
        response.setContentType("text/plain; charset=utf-8");
        response.getOutputStream().write(body.getBytes(StandardCharsets.UTF_8));
    }
}
