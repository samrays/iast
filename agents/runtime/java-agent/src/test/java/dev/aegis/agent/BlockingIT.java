package dev.aegis.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.api.io.TempDir;

/** Verifies blocking in a separate JVM against real Jetty and H2 sink calls. */
@EnabledIf("agentJarExists")
class BlockingIT {

    static boolean agentJarExists() {
        String jar = System.getProperty("aegis.agent.jar");
        return jar != null && Files.exists(Path.of(jar));
    }

    @Test
    void blocksOnlyAFlowWhosePayloadConfirmsExploitation(@TempDir Path temp) throws Exception {
        Path agentJar = Path.of(System.getProperty("aegis.agent.jar"));
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

        Path events = temp.resolve("blocking.ndjson");
        List<String> command =
                List.of(
                        Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                        "-javaagent:"
                                + agentJar
                                + "=application=blocking-probe,environment=DEVELOPMENT,"
                                + "packages=com.example,capture=FULL,blocking=true,endpoint=file:"
                                + events.toString().replace('\\', '/'),
                        "-cp",
                        String.join(File.pathSeparator, entries),
                        "com.example.corpus.BenchmarkApp");

        Process process = new ProcessBuilder(command).start();
        String stdout = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        String stderr = new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(180, TimeUnit.SECONDS), "blocking probe timed out");
        assertEquals(0, process.exitValue(), "blocking probe failed:\n" + stdout + stderr);

        String exploited = caseLine(stdout, "/sql/plus");
        String confirmed = caseLine(stdout, "/sql/confirmed");
        String safe = caseLine(stdout, "/sql/confirmed-constant");
        assertTrue(exploited.contains("handled:SecurityException"), exploited);
        assertTrue(confirmed.contains("200:rows:"), confirmed);
        assertTrue(!confirmed.contains("SecurityException"), confirmed);
        assertTrue(safe.contains("200:rows:"), safe);
        assertTrue(!safe.contains("SecurityException"), safe);

        String wire = Files.readString(events, StandardCharsets.UTF_8);
        assertTrue(
                wire.lines()
                        .anyMatch(
                                line ->
                                        line.contains("\"path\":\"/sql/plus\"")
                                                && line.contains("CONFIDENCE_EXPLOITED")),
                wire);
        assertTrue(
                wire.lines()
                        .anyMatch(
                                line ->
                                        line.contains("\"path\":\"/sql/confirmed\"")
                                                && line.contains("CONFIDENCE_CONFIRMED")),
                wire);
    }

    private static String caseLine(String stdout, String path) {
        return stdout.lines()
                .filter(line -> line.startsWith("CASE " + path + " "))
                .findFirst()
                .orElseThrow(() -> new AssertionError("missing " + path + " in:\n" + stdout));
    }
}
