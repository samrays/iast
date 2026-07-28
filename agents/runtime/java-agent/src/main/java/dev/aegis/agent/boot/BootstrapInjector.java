package dev.aegis.agent.boot;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.instrument.Instrumentation;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.CodeSource;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

/**
 * Publishes the agent's runtime classes to the bootstrap class loader.
 *
 * <p>Advice is <em>inlined</em> into the method it instruments. A hook placed in
 * {@code java.lang.StringBuilder} therefore executes as bootstrap-loaded code, and bootstrap
 * code cannot see the system class path — so {@code AgentRuntime} must live on the bootstrap
 * search path or every JDK-core hook dies with {@code NoClassDefFoundError}.
 *
 * <p>The subtlety that matters, and the one that is easy to get wrong: <b>only</b> the runtime
 * classes go across. Appending the whole agent jar would put the shaded Byte Buddy on both the
 * bootstrap and the system path, and the JVM would then see two distinct {@code AgentBuilder}
 * types and refuse to link the agent's own bootstrap code:
 *
 * <pre>
 *   LinkageError: loader constraint violation ... have different Class objects for the type
 *   dev/aegis/shaded/bytebuddy/agent/builder/AgentBuilder used in the signature
 * </pre>
 *
 * <p>Byte Buddy stays on the system path where the agent uses it; the runtime goes to
 * bootstrap where the advice needs it. Because the bootstrap loader is the parent of the
 * system loader, the agent's own references resolve to the same bootstrap copies, so there is
 * exactly one {@code AgentRuntime} and one static instance field in the process.
 */
public final class BootstrapInjector {

    /** Packages the inlined advice reaches. Everything else stays on the system path. */
    private static final String[] BOOTSTRAP_PACKAGES = {
        "dev/aegis/agent/taint/",
        "dev/aegis/agent/runtime/",
        "dev/aegis/agent/detect/",
        "dev/aegis/agent/redact/",
        "dev/aegis/agent/report/",
    };

    /** Top-level classes in {@code dev.aegis.agent} that the advice calls directly. */
    private static final String[] BOOTSTRAP_CLASSES = {
        "dev/aegis/agent/AgentRuntime",
        "dev/aegis/agent/AttackSignatures",
    };

    // AgentConfig is deliberately absent. The bytecode verifier resolves the types named in
    // AegisAgent.install() when it loads that class — which happens before injection can
    // run — so a bootstrap copy of AgentConfig would end up split across two loaders and
    // throw IllegalAccessError on its own inner Builder. Configuration therefore stays on
    // the system path and crosses to the runtime as plain JDK types.

    private BootstrapInjector() {}

    /**
     * Build a jar of the runtime classes and append it to the bootstrap search path.
     *
     * <p>Must run before anything in {@code install} touches {@code AgentRuntime} or
     * {@code AgentConfig}: once the system loader has defined one of those, appending a
     * second copy to bootstrap produces the very loader-constraint violation this method
     * exists to avoid.
     *
     * @return true when instrumentation of JDK core types is now possible
     */
    public static boolean inject(Instrumentation instrumentation) {
        try {
            File agentJar = locateAgentJar();
            if (agentJar == null || !agentJar.isFile()) {
                // Running from a directory, as the unit tests do. JDK-core instrumentation is
                // unavailable; the integration suite covers that path against the real jar.
                return false;
            }

            Path bootstrapJar = Files.createTempFile("aegis-bootstrap", ".jar");
            bootstrapJar.toFile().deleteOnExit();

            int copied = 0;
            try (JarFile source = new JarFile(agentJar);
                    JarOutputStream out =
                            new JarOutputStream(Files.newOutputStream(bootstrapJar))) {
                Enumeration<JarEntry> entries = source.entries();
                while (entries.hasMoreElements()) {
                    JarEntry entry = entries.nextElement();
                    if (entry.isDirectory() || !belongsOnBootstrap(entry.getName())) {
                        continue;
                    }
                    out.putNextEntry(new JarEntry(entry.getName()));
                    try (InputStream in = source.getInputStream(entry)) {
                        copy(in, out);
                    }
                    out.closeEntry();
                    copied++;
                }
            }

            if (copied == 0) {
                return false;
            }
            instrumentation.appendToBootstrapClassLoaderSearch(new JarFile(bootstrapJar.toFile()));
            return true;
        } catch (IOException | URISyntaxException | RuntimeException e) {
            if (Boolean.getBoolean("aegis.debug")) {
                System.err.println("[aegis] bootstrap injection failed: " + e);
            }
            return false;
        }
    }

    static boolean belongsOnBootstrap(String entryName) {
        if (!entryName.endsWith(".class")) {
            return false;
        }
        for (String prefix : BOOTSTRAP_PACKAGES) {
            if (entryName.startsWith(prefix)) {
                return true;
            }
        }
        for (String name : BOOTSTRAP_CLASSES) {
            // Include nested classes such as AgentRuntime$1 alongside the outer type.
            if (entryName.equals(name + ".class") || entryName.startsWith(name + "$")) {
                return true;
            }
        }
        return false;
    }

    private static File locateAgentJar() throws URISyntaxException {
        CodeSource source = BootstrapInjector.class.getProtectionDomain().getCodeSource();
        if (source == null || source.getLocation() == null) {
            return null;
        }
        return new File(source.getLocation().toURI());
    }

    private static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) != -1) {
            out.write(buffer, 0, read);
        }
    }
}
