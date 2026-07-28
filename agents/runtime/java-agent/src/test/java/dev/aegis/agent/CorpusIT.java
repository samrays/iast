package dev.aegis.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.aegis.agent.corpus.BenchmarkApp;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.api.io.TempDir;

/**
 * The detection gate: does the agent find the real defects, and does it stay quiet otherwise?
 *
 * <p>A scanner that reports everything catches every vulnerability and is worthless, so both
 * numbers are asserted. The corpus pairs each vulnerable case with a sibling that differs only
 * in the one thing that makes it safe — a bound parameter instead of a concatenated one, a
 * constant instead of user input, an equal value that is not the same object.
 *
 * <p>Recorded here because it is the number a customer will ask for: the agent must be at
 * <b>100% recall and 0% false positives</b> on this corpus, and the build fails otherwise.
 */
@EnabledIf("agentJarExists")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CorpusIT {

    private static Path agentJar;
    private static String classpath;

    /** Findings by request path, from one run shared across the assertions below. */
    private Map<String, List<String>> findings;
    private String stdout;

    static boolean agentJarExists() {
        String jar = System.getProperty("aegis.agent.jar");
        return jar != null && Files.exists(Path.of(jar));
    }

    @BeforeAll
    void runCorpus(@TempDir Path temp) throws Exception {
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

        Path eventsFile = temp.resolve("corpus.ndjson");
        List<String> command =
                List.of(
                        Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                        "-javaagent:"
                                + agentJar
                                + "=application=corpus,environment=DEVELOPMENT,"
                                + "packages=dev.aegis.agent.corpus;dev.aegis.agent.demo,"
                                + "capture=FULL,endpoint=file:"
                                + eventsFile.toString().replace('\\', '/'),
                        "-cp",
                        classpath,
                        "dev.aegis.agent.corpus.BenchmarkApp");

        Process process = new ProcessBuilder(command).start();
        stdout = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        String stderr = new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(180, TimeUnit.SECONDS), "corpus timed out");
        assertEquals(0, process.exitValue(), "corpus failed:\n" + stdout + stderr);

        findings = new LinkedHashMap<>();
        for (String path : BenchmarkApp.CASES.keySet()) {
            findings.put(path, new ArrayList<>());
        }
        for (String line : Files.readAllLines(eventsFile)) {
            if (line.isBlank() || !line.contains("EVENT_TYPE_TAINT_HIT")) {
                continue;
            }
            for (String path : BenchmarkApp.CASES.keySet()) {
                if (line.contains("\"path\":\"" + path + "\"")) {
                    findings.get(path).add(line);
                }
            }
        }
    }

    @Test
    @DisplayName("every vulnerable case is found, with the right rule")
    void recallIsComplete() {
        List<String> missed = new ArrayList<>();
        for (Map.Entry<String, String[]> entry : BenchmarkApp.CASES.entrySet()) {
            String path = entry.getKey();
            if (!BenchmarkApp.Expectation.VULNERABLE.name().equals(entry.getValue()[0])) {
                continue;
            }
            String expectedRule = entry.getValue()[1];
            boolean found =
                    findings.get(path).stream()
                            .anyMatch(line -> line.contains("\"rule_key\":\"" + expectedRule + "\""));
            if (!found) {
                missed.add(path + " (expected " + expectedRule + ")");
            }
        }
        assertTrue(missed.isEmpty(), "missed " + missed.size() + " defects: " + missed);
    }

    @Test
    @DisplayName("no safe case produces a finding")
    void thereAreNoFalsePositives() {
        List<String> spurious = new ArrayList<>();
        for (Map.Entry<String, String[]> entry : BenchmarkApp.CASES.entrySet()) {
            if (!BenchmarkApp.Expectation.SAFE.name().equals(entry.getValue()[0])) {
                continue;
            }
            for (String line : findings.get(entry.getKey())) {
                spurious.add(entry.getKey() + " -> " + line);
            }
        }
        // One false positive on correct code costs more trust than ten true positives earn.
        assertTrue(spurious.isEmpty(), "false positives:\n" + String.join("\n", spurious));
    }

    @Test
    @DisplayName("one defect reports once, however many times the JDK re-enters itself")
    void doesNotReportTheSameDefectTwice() {
        List<String> duplicated =
                BenchmarkApp.CASES.entrySet().stream()
                        .filter(e -> BenchmarkApp.Expectation.VULNERABLE.name().equals(e.getValue()[0]))
                        .filter(e -> findings.get(e.getKey()).size() > 1)
                        .map(e -> e.getKey() + " x" + findings.get(e.getKey()).size())
                        .collect(Collectors.toList());

        // Runtime.exec(String) delegates to its own overload, so a naive matcher fires twice for
        // one call. A developer shown the same defect twice stops reading the list.
        assertTrue(duplicated.isEmpty(), "duplicate findings: " + duplicated);
    }

    @Test
    @DisplayName("the agent never throws into the application")
    void neverBreaksTheApplication() {
        assertTrue(stdout.contains("HOOK_FAILURES=0"), stdout);
        assertTrue(stdout.contains("AGENT_PRESENT=true"), stdout);
    }

    @Test
    @DisplayName("`+` concatenation is tracked, not just StringBuilder")
    void tracksInvokedynamicConcatenation() {
        // Since Java 9 the compiler lowers `+` to an invokedynamic against StringConcatFactory.
        // This is the most common shape of SQL injection in Java, and an agent that only
        // instruments StringBuilder misses it silently.
        String finding =
                findings.get("/sql/plus").stream()
                        .findFirst()
                        .orElseThrow(() -> new AssertionError("`+` concatenation was not tracked"));
        assertTrue(finding.contains("\"rule_key\":\"sql-injection\""), finding);
        // And the offsets are right, not merely present: the payload starts after the prefix.
        assertTrue(finding.contains("\"start\":37"), finding);
    }
}
