package dev.aegis.agent.report;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

/**
 * Ships batches of events off the process.
 *
 * <p>Only ever called from the reporting thread. Nothing here may be invoked from an
 * application thread — that is the whole reason the ring buffer exists.
 */
public interface Transport {

    /**
     * Send already-serialized NDJSON lines.
     *
     * <p>Lines rather than events, because the offline spool replays text it read back from
     * disk and must go through exactly the same path as a live batch.
     *
     * @return true when the batch was accepted, so the caller can advance its spool cursor.
     *     False means "keep it and retry"; it must not throw.
     */
    boolean sendLines(List<String> jsonLines);

    /** Serialize and send. */
    default boolean send(List<RuntimeEvent> batch) {
        if (batch.isEmpty()) {
            return true;
        }
        List<String> lines = new ArrayList<>(batch.size());
        for (RuntimeEvent event : batch) {
            lines.add(event.toJson());
        }
        return sendLines(lines);
    }

    /**
     * NDJSON over HTTP — the fallback transport from ADR-0005, and the default here.
     *
     * <p>Built on {@link HttpURLConnection} rather than the far nicer {@code java.net.http}
     * client, for one hard reason: this class is published to the <b>bootstrap</b> class
     * loader so the inlined advice can reach the runtime, and bootstrap code can only see
     * {@code java.base}. {@code java.net.http.HttpClient} lives in its own module, loaded by
     * the platform loader, so touching it from here fails at runtime with
     * {@code NoClassDefFoundError: java/net/http/HttpClient} — after the agent has already
     * reported itself installed.
     */
    final class Http implements Transport {

        private static final int CONNECT_TIMEOUT_MS = 5_000;
        private static final int READ_TIMEOUT_MS = 10_000;

        private final String endpoint;
        private final String credential;
        private final SSLSocketFactory pinnedFactory;
        private final boolean pinningRequired;

        public Http(String endpoint, String credential) {
            this(endpoint, credential, CertificatePinner.parse(null));
        }

        public Http(String endpoint, String credential, CertificatePinner pinner) {
            this.endpoint = endpoint.replaceAll("/$", "") + "/ingest/v1/events";
            this.credential = credential == null ? "" : credential;
            this.pinningRequired = pinner != null && pinner.isEnabled();
            this.pinnedFactory = pinner == null ? null : pinner.socketFactory();
        }

        /** True when pins were configured but the pinned TLS context could not be built. */
        public boolean isMisconfigured() {
            return pinningRequired && pinnedFactory == null;
        }

        @Override
        public boolean sendLines(List<String> jsonLines) {
            if (jsonLines.isEmpty()) {
                return true;
            }
            if (isMisconfigured()) {
                // Pins were requested and could not be enforced. Sending anyway would quietly
                // downgrade to ordinary TLS — the exact outcome pinning exists to prevent.
                return false;
            }
            HttpURLConnection connection = null;
            try {
                StringBuilder body = new StringBuilder(jsonLines.size() * 512);
                for (String line : jsonLines) {
                    body.append(line).append('\n');
                }
                byte[] payload = body.toString().getBytes(StandardCharsets.UTF_8);

                connection = (HttpURLConnection) new URL(endpoint).openConnection();
                if (connection instanceof HttpsURLConnection secure && pinnedFactory != null) {
                    // Set on the connection, so the pin is checked during the handshake —
                    // before a single byte of customer data is written. Inspecting the chain
                    // after the response would be far too late.
                    secure.setSSLSocketFactory(pinnedFactory);
                } else if (pinningRequired) {
                    // Pinned agent pointed at a plaintext endpoint: refuse rather than send.
                    return false;
                }
                connection.setRequestMethod("POST");
                connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
                connection.setReadTimeout(READ_TIMEOUT_MS);
                connection.setDoOutput(true);
                connection.setInstanceFollowRedirects(false);
                connection.setRequestProperty("Content-Type", "application/x-ndjson");
                connection.setRequestProperty("Authorization", "Bearer " + credential);
                connection.setFixedLengthStreamingMode(payload.length);

                try (OutputStream out = connection.getOutputStream()) {
                    out.write(payload);
                }

                int status = connection.getResponseCode();
                // Drain the body so the connection can be pooled rather than torn down.
                drainQuietly(connection);

                if (status == 400 || status == 413) {
                    // The bytes themselves are invalid or too large, so retrying them cannot
                    // succeed. Authentication failures are deliberately excluded: credentials
                    // can be renewed or corrected, and losing a confirmed finding during that
                    // window would make a control-plane outage look like a clean application.
                    return true;
                }
                return status / 100 == 2;
            } catch (Exception e) {
                // The control plane being unreachable is not the application's problem. The
                // batch stays queued and the agent tries again.
                return false;
            } finally {
                if (connection != null) {
                    connection.disconnect();
                }
            }
        }

        private static void drainQuietly(HttpURLConnection connection) {
            try (java.io.InputStream stream =
                    connection.getResponseCode() >= 400
                            ? connection.getErrorStream()
                            : connection.getInputStream()) {
                if (stream != null) {
                    byte[] buffer = new byte[4096];
                    while (stream.read(buffer) != -1) {
                        // discard
                    }
                }
            } catch (IOException ignored) {
                // Nothing useful to do; the status code is what mattered.
            }
        }
    }

    /**
     * Appends NDJSON to a file.
     *
     * <p>Used by the integration tests and by air-gapped deployments that ship telemetry out
     * of band. It writes the identical format the HTTP transport posts, so a file captured in
     * an isolated network can be replayed into the gateway unchanged.
     */
    final class File implements Transport {

        private final Path path;

        public File(Path path) {
            this.path = path;
        }

        @Override
        public boolean sendLines(List<String> jsonLines) {
            if (jsonLines.isEmpty()) {
                return true;
            }
            StringBuilder body = new StringBuilder(jsonLines.size() * 512);
            for (String line : jsonLines) {
                body.append(line).append('\n');
            }
            try {
                if (path.getParent() != null) {
                    Files.createDirectories(path.getParent());
                }
                try (OutputStream out =
                        Files.newOutputStream(
                                path,
                                StandardOpenOption.CREATE,
                                StandardOpenOption.WRITE,
                                StandardOpenOption.APPEND)) {
                    out.write(body.toString().getBytes(StandardCharsets.UTF_8));
                }
                return true;
            } catch (IOException e) {
                return false;
            }
        }
    }

    /** Discards everything. The agent's behaviour when it has nowhere to report. */
    final class Noop implements Transport {
        @Override
        public boolean sendLines(List<String> jsonLines) {
            return true;
        }
    }

    /** Choose a transport from the configured endpoint. */
    static Transport forEndpoint(String endpoint, String credential, String pins) {
        if (endpoint == null || endpoint.isBlank()) {
            return new Noop();
        }
        if (endpoint.startsWith("file:")) {
            return new File(Path.of(endpoint.substring("file:".length())));
        }
        return new Http(endpoint, credential, CertificatePinner.parse(pins));
    }
}
