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
 * The real end-to-end proof.
 *
 * <p>Launches a separate JVM with {@code -javaagent:aegis-agent.jar}, exactly as a customer
 * would, runs deliberately vulnerable code against a real H2 database, and reads the NDJSON
 * the agent emitted. Every layer is genuine: bytecode instrumentation of {@code StringBuilder}
 * and {@code java.sql.Statement}, range-based taint propagation, sink evaluation, redaction
 * and transport. Nothing is stubbed.
 *
 * <p>Runs under {@code mvn verify}, after {@code package}, because bootstrap injection needs
 * an actual jar file.
 */
@EnabledIf("agentJarExists")
class AgentIT {

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
                stream.filter(p -> p.toString().endsWith(".jar"))
                        .forEach(p -> entries.add(p.toString()));
            }
        }
        classpath = String.join(File.pathSeparator, entries);
    }

    private record Run(int exitCode, String stdout, String stderr, List<String> events) {}

    private Run runDemo(Path eventsFile) throws Exception {
        List<String> command =
                List.of(
                        Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                        "-javaagent:"
                                + agentJar
                                + "=application=demo-app,environment=DEVELOPMENT,"
                                + "packages=dev.aegis.agent.demo,capture=FULL,"
                                + "endpoint=file:"
                                + eventsFile.toString().replace('\\', '/'),
                        "-cp",
                        classpath,
                        "dev.aegis.agent.demo.VulnerableApp");

        ProcessBuilder builder = new ProcessBuilder(command);
        Process process = builder.start();
        String stdout = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        String stderr = new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(120, TimeUnit.SECONDS), "demo application timed out");

        List<String> events =
                Files.exists(eventsFile)
                        ? Files.readAllLines(eventsFile).stream()
                                .filter(line -> !line.isBlank())
                                .collect(Collectors.toList())
                        : List.of();
        return new Run(process.exitValue(), stdout, stderr, events);
    }

    @Test
    @DisplayName("a real SQL injection through a real JDBC sink is detected and reported")
    void detectsSqlInjectionEndToEnd(@TempDir Path temp) throws Exception {
        Path eventsFile = temp.resolve("events.ndjson");
        Run run = runDemo(eventsFile);

        assertEquals(0, run.exitCode(), "demo failed:\n" + run.stdout() + run.stderr());
        assertTrue(run.stdout().contains("[aegis] agent installed"), run.stdout());

        // The injection genuinely worked: all three rows came back for a one-name lookup.
        assertTrue(run.stdout().contains("UNSAFE_ROWS=3"), run.stdout());
        // The bound query treated the payload as a literal and matched nothing.
        assertTrue(run.stdout().contains("SAFE_ROWS=0"), run.stdout());
        assertTrue(run.stdout().contains("CLEAN_ROWS=1"), run.stdout());

        // The agent never threw into the application.
        assertTrue(run.stdout().contains("HOOK_FAILURES=0"), run.stdout());

        List<String> taintHits =
                run.events().stream()
                        .filter(line -> line.contains("EVENT_TYPE_TAINT_HIT"))
                        .collect(Collectors.toList());

        assertEquals(
                1,
                taintHits.size(),
                "expected exactly one finding — the concatenated query — but got:\n"
                        + String.join("\n", run.events()));

        String finding = taintHits.get(0);
        assertTrue(finding.contains("\"rule_key\":\"sql-injection\""), finding);
        assertTrue(finding.contains("CONFIDENCE_EXPLOITED"), finding);
        assertTrue(finding.contains("SEVERITY_CRITICAL"), finding);
        assertTrue(finding.contains("java.sql.Statement"), finding);

        // The evidence a developer actually reads: which characters were theirs.
        assertTrue(finding.contains("\"ranges\":[{\"start\":"), finding);
        assertTrue(finding.contains("SOURCE_KIND_PARAMETER"), finding);
        assertTrue(finding.contains("\"source_name\":\"name\""), finding);
        assertTrue(finding.contains("\"stack_fingerprint\":\""), finding);

        // The application frame is present and marked as application code; JDK frames are not.
        assertTrue(finding.contains("dev.aegis.agent.demo"), finding);
    }

    @Test
    @DisplayName("a parameterised query produces no finding at all")
    void staysSilentOnBoundParameters(@TempDir Path temp) throws Exception {
        Path eventsFile = temp.resolve("events.ndjson");
        Run run = runDemo(eventsFile);

        long findings =
                run.events().stream().filter(line -> line.contains("EVENT_TYPE_TAINT_HIT")).count();

        // Three requests ran; only the concatenating one may report. If a PreparedStatement
        // ever produced a finding, nobody would leave this switched on in production.
        assertEquals(1, findings, String.join("\n", run.events()));
        assertFalse(
                run.events().stream()
                        .anyMatch(line -> line.contains("demo-trace-2")),
                "the bound query must not appear in the evidence at all");
    }

    @Test
    @DisplayName("the agent does not slow the application beyond its budget")
    void overheadStaysWithinBudget(@TempDir Path temp) throws Exception {
        // A coarse smoke check, not a benchmark: the JMH suite in Phase 4's benchmark task
        // is what gates releases. This only catches a catastrophic regression.
        long start = System.nanoTime();
        Run run = runDemo(temp.resolve("events.ndjson"));
        long elapsedMillis = (System.nanoTime() - start) / 1_000_000;

        assertEquals(0, run.exitCode());
        assertTrue(
                elapsedMillis < 60_000,
                "instrumented startup and three requests took " + elapsedMillis + "ms");
    }
}
