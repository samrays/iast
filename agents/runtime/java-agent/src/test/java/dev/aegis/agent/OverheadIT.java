package dev.aegis.agent;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.EnabledIf;

/**
 * The overhead gate: the agent runs inside a business-critical process it does not own.
 *
 * <p>The customer's throughput matters more than our telemetry, always. This measures the same
 * workload with and without {@code -javaagent} and fails the build when instrumentation costs
 * more than the configured share of a request.
 *
 * <p>Runs are interleaved and the estimator is the <em>minimum</em> of each side. Interference
 * on a shared machine only ever makes a round slower, never faster, so the fastest observed
 * round is the closest available reading of what the code itself costs — and taking the fastest
 * baseline against the fastest instrumented run is the least flattering pairing available,
 * which is the right bias for a gate.
 */
@EnabledIf("agentJarExists")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OverheadIT {

    /**
     * Ceiling on the added share of a request.
     *
     * <p>Generous, deliberately. This is a regression gate on a CI runner of unknown speed and
     * load, not a marketing figure — its job is to catch the day someone puts an allocation
     * back on the hot path, not to certify a number. The measured value is printed on every
     * run so the trend is visible even while the gate stays quiet.
     */
    private static final double MAX_OVERHEAD_PERCENT =
            Double.parseDouble(System.getProperty("aegis.overhead.max.percent", "50"));

    private static final int PAIRS = Integer.parseInt(System.getProperty("aegis.overhead.pairs", "3"));

    private static Path agentJar;
    private static String classpath;

    private long baselineNanos;
    private long instrumentedNanos;

    static boolean agentJarExists() {
        String jar = System.getProperty("aegis.agent.jar");
        return jar != null && Files.exists(Path.of(jar));
    }

    @BeforeAll
    void measure() throws Exception {
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

        baselineNanos = Long.MAX_VALUE;
        instrumentedNanos = Long.MAX_VALUE;
        for (int pair = 0; pair < PAIRS; pair++) {
            // Interleaved, so a machine that slows down partway through penalises both sides.
            baselineNanos = Math.min(baselineNanos, run(false));
            instrumentedNanos = Math.min(instrumentedNanos, run(true));
        }

        System.out.printf(
                "[aegis] overhead: baseline %,dns instrumented %,dns (+%,dns, %+.1f%%)%n",
                baselineNanos,
                instrumentedNanos,
                instrumentedNanos - baselineNanos,
                overheadPercent());
    }

    private long run(boolean instrumented) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        if (instrumented) {
            command.add(
                    "-javaagent:"
                            + agentJar
                            + "=application=bench,environment=DEVELOPMENT,"
                            + "packages=com.example.bench,capture=NONE,endpoint=");
        }
        command.add("-cp");
        command.add(classpath);
        command.add("com.example.bench.BenchmarkWorkload");

        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(300, TimeUnit.SECONDS), "workload timed out");
        assertTrue(process.exitValue() == 0, "workload failed:\n" + output);

        if (instrumented) {
            assertTrue(output.contains("AGENT_PRESENT=true"), "the agent did not install:\n" + output);
        }
        return output.lines()
                .filter(line -> line.startsWith("NS_PER_REQUEST="))
                .map(line -> Long.parseLong(line.substring("NS_PER_REQUEST=".length()).trim()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no measurement in:\n" + output));
    }

    private double overheadPercent() {
        return ((double) (instrumentedNanos - baselineNanos) / baselineNanos) * 100.0;
    }

    @Test
    @DisplayName("instrumentation stays inside its overhead budget")
    void staysWithinBudget() {
        assertTrue(
                overheadPercent() < MAX_OVERHEAD_PERCENT,
                String.format(
                        "agent overhead was %+.1f%% (%,dns added per request), budget %.1f%%. "
                                + "The customer's throughput matters more than our telemetry.",
                        overheadPercent(), instrumentedNanos - baselineNanos, MAX_OVERHEAD_PERCENT));
    }

    @Test
    @DisplayName("the measurement itself is sane")
    void theBaselineIsCredible() {
        // A baseline of zero, or an instrumented run that came out faster than physics allows,
        // means the harness measured nothing and the gate above proved nothing.
        assertTrue(baselineNanos > 0, "baseline did not run");
        assertTrue(instrumentedNanos > 0, "instrumented run did not run");
    }
}
