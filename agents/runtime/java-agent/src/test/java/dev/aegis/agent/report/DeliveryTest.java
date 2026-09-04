package dev.aegis.agent.report;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Delivery: what happens to a finding between the ring buffer and the control plane.
 *
 * <p>This is the part of the agent that decides whether an outage on our side becomes a blind
 * spot on the customer's, so the tests are about failure rather than success.
 */
class DeliveryTest {

    /** Records what it was asked to send and can be told to start or stop accepting. */
    private static final class ControllableTransport implements Transport {
        private final List<String> delivered = new ArrayList<>();
        private final AtomicInteger attempts = new AtomicInteger();
        private volatile boolean healthy = true;

        @Override
        public boolean sendLines(List<String> jsonLines) {
            attempts.incrementAndGet();
            if (!healthy) {
                return false;
            }
            delivered.addAll(jsonLines);
            return true;
        }
    }

    private static Reporter reporterWith(int findings) {
        Reporter reporter = new Reporter(1024);
        for (int index = 0; index < findings; index++) {
            reporter.reportCoverageGap("gap-" + index, "component-" + index);
        }
        return reporter;
    }

    @Nested
    @DisplayName("Spool")
    class SpoolTests {

        @Test
        @DisplayName("survives a restart: what was written is what is read back")
        void roundTrips(@TempDir Path temp) {
            Spool spool = new Spool(temp.resolve("spool"), 1024 * 1024);
            spool.append(List.of("{\"event_id\":\"a\"}", "{\"event_id\":\"b\"}"));

            // A fresh instance, as after a JVM restart. The point of a durable spool is that
            // findings collected before a deploy are still delivered after it.
            Spool reopened = new Spool(temp.resolve("spool"), 1024 * 1024);
            List<Path> pending = reopened.pending();
            assertEquals(1, pending.size());
            assertEquals(
                    List.of("{\"event_id\":\"a\"}", "{\"event_id\":\"b\"}"),
                    reopened.read(pending.get(0)));
        }

        @Test
        @DisplayName("discarding a segment removes it")
        void discards(@TempDir Path temp) {
            Spool spool = new Spool(temp, 1024 * 1024);
            spool.append(List.of("{\"event_id\":\"a\"}"));
            spool.discard(spool.pending().get(0));
            assertTrue(spool.pending().isEmpty());
        }

        @Test
        @DisplayName("stays inside its ceiling by dropping the oldest, and says how many it lost")
        void enforcesCeiling(@TempDir Path temp) {
            // The ceiling floors at one segment, so this is the smallest spool that can exist.
            Spool spool = new Spool(temp, Spool.SEGMENT_BYTES);
            String line = "{\"padding\":\"" + "x".repeat(4096) + "\"}";

            for (int batch = 0; batch < 400; batch++) {
                spool.append(List.of(line));
            }

            // An unbounded spool inside a customer's container eventually fills their disk,
            // which is a far worse outcome than losing the oldest telemetry.
            assertTrue(
                    spool.sizeBytes() <= Spool.SEGMENT_BYTES * 2,
                    "spool grew to " + spool.sizeBytes() + " bytes");
            assertTrue(spool.droppedEvents() > 0, "dropped nothing despite exceeding the ceiling");
        }

        @Test
        @DisplayName("rolls to a new segment rather than growing one file forever")
        void rollsSegments(@TempDir Path temp) {
            Spool spool = new Spool(temp, 64L * 1024 * 1024);
            String line = "{\"padding\":\"" + "x".repeat(200_000) + "\"}";
            for (int batch = 0; batch < 12; batch++) {
                spool.append(List.of(line));
            }
            assertTrue(
                    spool.pending().size() > 1,
                    "everything landed in one segment; a crash mid-replay would re-send all of it");
        }

        @Test
        @DisplayName("a spool that cannot be written disables itself instead of retrying")
        void disablesOnFailure(@TempDir Path temp) throws IOException {
            // A file where the spool directory should be: createDirectories cannot succeed.
            Path blocked = temp.resolve("blocked");
            Files.writeString(blocked, "not a directory");

            Spool spool = new Spool(blocked, 1024 * 1024);
            spool.append(List.of("{\"event_id\":\"a\"}"));

            // A read-only volume is the operator's problem to fix. The agent's job at that
            // point is to stop touching the disk and keep the application running.
            assertTrue(spool.isDisabled());
            assertTrue(spool.pending().isEmpty());
        }
    }

    @Nested
    @DisplayName("ReportingThread")
    class Delivery {

        @Test
        @DisplayName("an unreachable control plane spools the batch instead of losing it")
        void spoolsOnFailure(@TempDir Path temp) {
            ControllableTransport transport = new ControllableTransport();
            transport.healthy = false;
            Spool spool = new Spool(temp, 1024 * 1024);

            ReportingThread reporting =
                    new ReportingThread(reporterWith(3), transport, 1_000, spool);
            reporting.flushOnce();

            assertTrue(transport.delivered.isEmpty());
            assertEquals(1, reporting.spooledBatches());
            assertEquals(3, spool.read(spool.pending().get(0)).size());
        }

        @Test
        @DisplayName("recovery replays the spool oldest-first and clears it")
        void replaysOnRecovery(@TempDir Path temp) {
            ControllableTransport transport = new ControllableTransport();
            Spool spool = new Spool(temp, 1024 * 1024);
            Reporter reporter = reporterWith(2);

            ReportingThread reporting = new ReportingThread(reporter, transport, 1_000, spool);
            transport.healthy = false;
            reporting.flushOnce();
            assertFalse(spool.pending().isEmpty());

            transport.healthy = true;
            reporting.flushOnce();

            assertTrue(spool.pending().isEmpty(), "spool was not drained after recovery");
            assertEquals(2, transport.delivered.size());
            assertEquals(1, reporting.replayedBatches());
        }

        @Test
        @DisplayName("a segment is deleted only after the control plane accepts it")
        void keepsSegmentsUntilAcknowledged(@TempDir Path temp) {
            ControllableTransport transport = new ControllableTransport();
            Spool spool = new Spool(temp, 1024 * 1024);
            ReportingThread reporting =
                    new ReportingThread(reporterWith(1), transport, 1_000, spool);

            transport.healthy = false;
            reporting.flushOnce();
            int spooled = spool.pending().size();
            reporting.flushOnce();

            // Still down: nothing may be thrown away on the strength of an attempt.
            assertEquals(spooled, spool.pending().size());
        }

        @Test
        @DisplayName("backs off while down and snaps back the moment it recovers")
        void backsOff(@TempDir Path temp) {
            ControllableTransport transport = new ControllableTransport();
            ReportingThread reporting =
                    new ReportingThread(reporterWith(1), transport, 1_000, new Spool(temp, 1 << 20));

            transport.healthy = false;
            reporting.flushOnce();
            assertEquals(2, reporting.backoffMultiplier());
            reporting.flushOnce();
            assertEquals(4, reporting.backoffMultiplier());

            // Asymmetric on purpose: gradual recovery would only delay findings already in hand.
            transport.healthy = true;
            reporting.flushOnce();
            assertEquals(1, reporting.backoffMultiplier());
        }

        @Test
        @DisplayName("the backoff is capped, so a returning endpoint is noticed")
        void capsBackoff(@TempDir Path temp) {
            ControllableTransport transport = new ControllableTransport();
            transport.healthy = false;
            Reporter reporter = new Reporter(1024);
            ReportingThread reporting =
                    new ReportingThread(reporter, transport, 1_000, new Spool(temp, 1 << 20));

            for (int cycle = 0; cycle < 20; cycle++) {
                reporter.reportCoverageGap("gap-" + cycle, "component");
                reporting.flushOnce();
            }
            assertEquals(ReportingThread.MAX_BACKOFF_MULTIPLIER, reporting.backoffMultiplier());
        }

        @Test
        @DisplayName("works without a spool at all")
        void toleratesNoSpool() {
            ControllableTransport transport = new ControllableTransport();
            transport.healthy = false;
            ReportingThread reporting = new ReportingThread(reporterWith(1), transport, 1_000);

            reporting.flushOnce();

            // Spooling is opt-in: writing to disk inside someone else's container is the
            // operator's decision, and a read-only root filesystem is a correct one.
            assertEquals(0, reporting.spooledBatches());
        }
    }

    @Nested
    @DisplayName("HTTP transport")
    class Http {

        private HttpServer serve(int status, AtomicInteger requests) throws IOException {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext(
                    "/ingest/v1/events",
                    exchange -> {
                        requests.incrementAndGet();
                        exchange.getRequestBody().readAllBytes();
                        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
                        exchange.sendResponseHeaders(status, body.length);
                        try (OutputStream out = exchange.getResponseBody()) {
                            out.write(body);
                        }
                    });
            server.start();
            return server;
        }

        @Test
        @DisplayName("a 2xx is delivery")
        void acceptsSuccess() throws IOException {
            AtomicInteger requests = new AtomicInteger();
            HttpServer server = serve(200, requests);
            try {
                Transport transport =
                        Transport.forEndpoint(
                                "http://127.0.0.1:" + server.getAddress().getPort(), "token", "");
                assertTrue(transport.sendLines(List.of("{\"event_id\":\"a\"}")));
                assertEquals(1, requests.get());
            } finally {
                server.stop(0);
            }
        }

        @Test
        @DisplayName("a 5xx is retryable — the batch is kept")
        void retriesServerErrors() throws IOException {
            AtomicInteger requests = new AtomicInteger();
            HttpServer server = serve(503, requests);
            try {
                Transport transport =
                        Transport.forEndpoint(
                                "http://127.0.0.1:" + server.getAddress().getPort(), "token", "");
                assertFalse(transport.sendLines(List.of("{\"event_id\":\"a\"}")));
            } finally {
                server.stop(0);
            }
        }

        @Test
        @DisplayName("authentication failures are retryable after credential recovery")
        void reportsAuthenticationFailuresAsRetryable() throws IOException {
            for (int status : List.of(401, 403)) {
                AtomicInteger requests = new AtomicInteger();
                HttpServer server = serve(status, requests);
                try {
                    Transport transport =
                            Transport.forEndpoint(
                                    "http://127.0.0.1:" + server.getAddress().getPort(),
                                    "expired-token",
                                    "");
                    assertFalse(
                            transport.sendLines(List.of("{\"event_id\":\"a\"}")),
                            "status " + status + " must keep the finding for replay");
                } finally {
                    server.stop(0);
                }
            }
        }

        @Test
        @DisplayName("invalid or oversized bytes are dropped instead of poisoning the spool")
        void dropsPermanentPayloadRejections() throws IOException {
            for (int status : List.of(400, 413)) {
                AtomicInteger requests = new AtomicInteger();
                HttpServer server = serve(status, requests);
                try {
                    Transport transport =
                            Transport.forEndpoint(
                                    "http://127.0.0.1:" + server.getAddress().getPort(),
                                    "token",
                                    "");
                    assertTrue(
                            transport.sendLines(List.of("{\"event_id\":\"a\"}")),
                            "status " + status + " cannot become valid on retry");
                } finally {
                    server.stop(0);
                }
            }
        }

        @Test
        @DisplayName("an unreachable endpoint is a failure, not an exception")
        void survivesConnectionRefused() {
            Transport transport = Transport.forEndpoint("http://127.0.0.1:1", "token", "");
            assertFalse(transport.sendLines(List.of("{\"event_id\":\"a\"}")));
        }

        @Test
        @DisplayName("a pinned agent refuses to send over plaintext rather than downgrade")
        void refusesPlaintextWhenPinned() throws IOException {
            AtomicInteger requests = new AtomicInteger();
            HttpServer server = serve(200, requests);
            try {
                Transport transport =
                        Transport.forEndpoint(
                                "http://127.0.0.1:" + server.getAddress().getPort(),
                                "token",
                                "sha256/" + "A".repeat(43) + "=");
                assertFalse(transport.sendLines(List.of("{\"event_id\":\"a\"}")));
                assertEquals(0, requests.get(), "customer data was sent to an unpinned endpoint");
            } finally {
                server.stop(0);
            }
        }

        @Test
        @DisplayName("an empty batch is a no-op, not a request")
        void skipsEmptyBatches() {
            assertTrue(Transport.forEndpoint("http://127.0.0.1:1", "t", "").sendLines(List.of()));
        }
    }

    @Nested
    @DisplayName("Certificate pinning")
    class Pinning {

        /** Real certificates from the platform trust store — no fixtures, no fakes. */
        private X509Certificate[] platformCertificates() throws Exception {
            TrustManagerFactory factory =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init((KeyStore) null);
            for (TrustManager manager : factory.getTrustManagers()) {
                if (manager instanceof X509TrustManager trust) {
                    return trust.getAcceptedIssuers();
                }
            }
            return new X509Certificate[0];
        }

        @Test
        @DisplayName("blank configuration means ordinary TLS, not broken TLS")
        void disabledByDefault() {
            assertFalse(CertificatePinner.parse(null).isEnabled());
            assertFalse(CertificatePinner.parse("   ").isEnabled());
        }

        @Test
        @DisplayName("a malformed pin is ignored rather than fatal")
        void ignoresMalformedPins() {
            // It cannot weaken anything: an unparsed pin is simply absent. Refusing to start
            // over a typo in an optional setting would be the worse failure.
            assertFalse(CertificatePinner.parse("not-a-pin,sha256/").isEnabled());
            assertTrue(CertificatePinner.parse("junk,sha256/abc").isEnabled());
        }

        @Test
        @DisplayName("a pin matches the key it was computed from")
        void matchesTheRightKey() throws Exception {
            X509Certificate[] certificates = platformCertificates();
            org.junit.jupiter.api.Assumptions.assumeTrue(certificates.length >= 2);

            String pin = CertificatePinner.pinFor(certificates[0]);
            assertTrue(pin.startsWith("sha256/"));
            assertTrue(CertificatePinner.parse(pin).matches(certificates));
        }

        @Test
        @DisplayName("a different key does not match, however valid its chain")
        void rejectsTheWrongKey() throws Exception {
            X509Certificate[] certificates = platformCertificates();
            org.junit.jupiter.api.Assumptions.assumeTrue(certificates.length >= 2);

            // This is the whole point: a chain a public CA would happily validate must still be
            // refused when it is not the key we pinned.
            CertificatePinner pinner = CertificatePinner.parse(CertificatePinner.pinFor(certificates[0]));
            assertFalse(pinner.matches(new X509Certificate[] {certificates[1]}));
        }

        @Test
        @DisplayName("any certificate in the chain may match, so a leaf can rotate")
        void matchesAnywhereInTheChain() throws Exception {
            X509Certificate[] certificates = platformCertificates();
            org.junit.jupiter.api.Assumptions.assumeTrue(certificates.length >= 3);

            // Pinning an intermediate lets the leaf be renewed without a fleet-wide agent
            // update — which is what stops a pinned deployment becoming an outage on renewal day.
            CertificatePinner pinner = CertificatePinner.parse(CertificatePinner.pinFor(certificates[2]));
            assertTrue(
                    pinner.matches(
                            new X509Certificate[] {certificates[0], certificates[1], certificates[2]}));
        }

        @Test
        @DisplayName("an empty chain never matches")
        void rejectsEmptyChain() throws Exception {
            CertificatePinner pinner = CertificatePinner.parse("sha256/" + "A".repeat(43) + "=");
            assertFalse(pinner.matches(new X509Certificate[0]));
            assertFalse(pinner.matches(null));
        }

        @Test
        @DisplayName("an enabled pinner produces a usable socket factory")
        void buildsASocketFactory() {
            assertNotNull(
                    CertificatePinner.parse("sha256/" + "A".repeat(43) + "=").socketFactory());
        }
    }
}
