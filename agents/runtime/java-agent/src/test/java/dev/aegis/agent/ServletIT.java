package dev.aegis.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.api.io.TempDir;

/**
 * The agent against a real servlet container.
 *
 * <p>{@link AgentIT} proves the taint engine and the JDBC sink by driving the runtime directly.
 * This proves the part a customer actually depends on: that the agent finds the request
 * boundary on its own, recognises {@code getParameter} as a source without being told, and
 * carries taint from a container thread onto a pool thread — against a container it was never
 * compiled against.
 *
 * <p>One JVM, launched with {@code -javaagent}, running Jetty and answering its own HTTP calls.
 */
@EnabledIf("agentJarExists")
class ServletIT {

    private static Path agentJar;
    private static String classpath;

    static boolean agentJarExists() {
        String jar = System.getProperty("aegis.agent.jar");
        return jar != null && Files.exists(Path.of(jar));
    }

    @BeforeAll
    static void locateArtifacts() throws Exception {
        agentJar = Path.of(System.getProperty("aegis.agent.jar"));
        Path testClasses = Path.of(System.getProperty("aegis.test.classpath"));
        Path libs = agentJar.getParent().resolve("it-libs");

        List<String> entries = new ArrayList<>();
        entries.add(testClasses.toString());
        entries.add(agentJar.toString());
        if (Files.isDirectory(libs)) {
            try (var stream = Files.list(libs)) {
                stream.filter(path -> path.toString().endsWith(".jar"))
                        .forEach(path -> entries.add(path.toString()));
            }
        }
        classpath = String.join(File.pathSeparator, entries);
    }

    private record Run(int exitCode, String stdout, String stderr, List<String> events) {

        String requireLine(String key) {
            return stdout.lines()
                    .filter(line -> line.startsWith(key + "="))
                    .findFirst()
                    .map(line -> line.substring(key.length() + 1).trim())
                    .orElseThrow(() -> new AssertionError("no " + key + " in:\n" + stdout + stderr));
        }

        List<String> ofType(String type) {
            return events.stream().filter(line -> line.contains(type)).collect(Collectors.toList());
        }
    }

    private static Run runWebApp(Path eventsFile) throws Exception {
        return runWebApp("endpoint=file:" + eventsFile.toString().replace('\\', '/'), eventsFile);
    }

    private static Run runWebApp(String extraAgentArgs, Path eventsFile) throws Exception {
        List<String> command =
                List.of(
                        Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                        "-javaagent:"
                                + agentJar
                                + "=application=servlet-demo,environment=DEVELOPMENT,"
                                + "packages=com.example.app,capture=FULL,"
                                + extraAgentArgs,
                        "-cp",
                        classpath,
                        "com.example.app.ServletApp");

        Process process = new ProcessBuilder(command).start();
        String stdout = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        String stderr = new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(180, TimeUnit.SECONDS), "web application timed out");

        List<String> events =
                Files.exists(eventsFile)
                        ? Files.readAllLines(eventsFile).stream()
                                .filter(line -> !line.isBlank())
                                .collect(Collectors.toList())
                        : List.of();
        return new Run(process.exitValue(), stdout, stderr, events);
    }

    @Test
    @DisplayName("an injection arriving over real HTTP is found without the application's help")
    void findsInjectionThroughTheServletStack(@TempDir Path temp) throws Exception {
        Run run = runWebApp(temp.resolve("events.ndjson"));
        assertEquals(0, run.exitCode(), "application failed:\n" + run.stdout() + run.stderr());
        assertTrue(run.stdout().contains("[aegis] agent installed"), run.stdout());

        // The injection genuinely worked: a single-name lookup returned every row.
        assertEquals("3", run.requireLine("SEARCH_ROWS"));
        // The bound query treated the payload as a literal.
        assertEquals("0", run.requireLine("SAFE_ROWS"));
        assertEquals("0", run.requireLine("HOOK_FAILURES"));

        List<String> findings = run.ofType("EVENT_TYPE_TAINT_HIT");
        assertFalse(
                findings.isEmpty(),
                "the agent found nothing at all:\n" + String.join("\n", run.events()));

        String synchronous =
                findings.stream()
                        .filter(line -> line.contains("\"path\":\"/search\""))
                        .findFirst()
                        .orElseThrow(
                                () ->
                                        new AssertionError(
                                                "no finding for /search:\n"
                                                        + String.join("\n", findings)));

        assertTrue(synchronous.contains("\"rule_key\":\"sql-injection\""), synchronous);
        assertTrue(synchronous.contains("SEVERITY_CRITICAL"), synchronous);
        // The parameter was recognised as a source by instrumenting the container, not by the
        // application declaring it.
        assertTrue(synchronous.contains("SOURCE_KIND_PARAMETER"), synchronous);
        assertTrue(synchronous.contains("\"source_name\":\"name\""), synchronous);
        // Request evidence a developer can act on.
        assertTrue(synchronous.contains("\"method\":\"GET\""), synchronous);
        assertTrue(synchronous.contains("com.example.app.UserRepository"), synchronous);
    }

    @Test
    @DisplayName("taint survives the hand-off to a pool thread")
    void carriesContextAcrossThreads(@TempDir Path temp) throws Exception {
        Run run = runWebApp(temp.resolve("events.ndjson"));
        assertEquals(0, run.exitCode(), run.stdout() + run.stderr());

        // The parameter is read on the container thread; the sink executes on a pool thread.
        assertEquals("3", run.requireLine("ASYNC_ROWS"));

        boolean reported =
                run.ofType("EVENT_TYPE_TAINT_HIT").stream()
                        .anyMatch(line -> line.contains("\"path\":\"/async\""));
        assertTrue(
                reported,
                "the finding vanished at the thread boundary — a ThreadLocal-only taint table "
                        + "would look exactly like this:\n"
                        + String.join("\n", run.events()));
    }

    @Test
    @DisplayName("the correctly written endpoint produces nothing")
    void staysSilentOnTheSafeEndpoint(@TempDir Path temp) throws Exception {
        Run run = runWebApp(temp.resolve("events.ndjson"));

        assertTrue(
                run.ofType("EVENT_TYPE_TAINT_HIT").stream()
                        .noneMatch(line -> line.contains("\"path\":\"/safe\"")),
                "a parameterised query reported a finding; nobody would leave this switched on:\n"
                        + String.join("\n", run.events()));

        // Nor does merely reading a parameter and returning it produce one.
        assertTrue(
                run.ofType("EVENT_TYPE_TAINT_HIT").stream()
                        .noneMatch(line -> line.contains("\"path\":\"/echo\"")),
                String.join("\n", run.events()));
    }

    @Test
    @DisplayName("an unreachable control plane spools findings to disk instead of losing them")
    void spoolsWhenTheControlPlaneIsDown(@TempDir Path temp) throws Exception {
        Path spool = temp.resolve("spool");
        // Port 1 refuses immediately: a control plane that is genuinely down, not merely slow.
        Run run =
                runWebApp(
                        "endpoint=http://127.0.0.1:1,spool_dir="
                                + spool.toString().replace('\\', '/'),
                        temp.resolve("unused.ndjson"));

        assertEquals(0, run.exitCode(), "the application must not care:\n" + run.stderr());
        assertEquals("3", run.requireLine("SEARCH_ROWS"));
        assertEquals("0", run.requireLine("HOOK_FAILURES"));

        assertTrue(Files.isDirectory(spool), "nothing was spooled at all");
        List<String> spooled = new ArrayList<>();
        try (var segments = Files.list(spool)) {
            for (Path segment : segments.toList()) {
                spooled.addAll(Files.readAllLines(segment));
            }
        }

        // An outage on our side must not become a blind spot on the customer's.
        assertTrue(
                spooled.stream().anyMatch(line -> line.contains("\"rule_key\":\"sql-injection\"")),
                "the finding was lost when the endpoint refused:\n" + String.join("\n", spooled));
    }

    @Test
    @DisplayName("routes are discovered once each, not once per request")
    void discoversRoutesWithoutFlooding(@TempDir Path temp) throws Exception {
        Run run = runWebApp(temp.resolve("events.ndjson"));

        List<String> routes = run.ofType("EVENT_TYPE_ROUTE");
        assertFalse(routes.isEmpty(), "no routes discovered:\n" + String.join("\n", run.events()));

        for (String path : List.of("/search", "/safe", "/async", "/echo")) {
            long seen = routes.stream().filter(line -> line.contains("\"" + path + "\"")).count();
            assertEquals(1, seen, "route " + path + " reported " + seen + " times");
        }
    }
}
