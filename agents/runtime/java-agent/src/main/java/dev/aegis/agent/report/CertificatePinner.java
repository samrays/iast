package dev.aegis.agent.report;

import java.net.Socket;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Set;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * Public-key pinning for the agent's outbound connection.
 *
 * <p>The agent ships request parameters, headers and fragments of SQL — the most sensitive
 * data in the customer's process. Ordinary TLS trusts every certificate authority in the
 * platform trust store, so any one of them, or anything that can add a certificate to the host,
 * can terminate that connection and read all of it. Pinning narrows trust from "any public CA"
 * to "this specific key", which is the difference between a corporate TLS-inspection proxy
 * seeing customer data and it seeing nothing.
 *
 * <p>Pins are matched against the SHA-256 of the certificate's {@code SubjectPublicKeyInfo},
 * not of the certificate itself, so a renewed certificate carrying the same key still matches.
 * Any certificate in the presented chain may match: pinning an intermediate lets the leaf
 * rotate without a fleet-wide agent update, which is what stops a pinned deployment from
 * becoming an outage on renewal day.
 *
 * <p>Pinning <b>adds</b> to path validation, never replaces it. The platform trust manager runs
 * first, so an expired or untrusted chain fails before the pin is even considered.
 *
 * <p>Everything used here is in {@code java.base}, which this class needs: it is published to
 * the bootstrap class loader with the rest of the reporting package.
 */
public final class CertificatePinner {

    private static final String PREFIX = "sha256/";

    private final Set<String> pins;

    private CertificatePinner(Set<String> pins) {
        this.pins = pins;
    }

    /**
     * Parse configured pins.
     *
     * @param specification comma-separated {@code sha256/<base64>} entries; blank disables
     *     pinning and falls back to ordinary path validation
     */
    public static CertificatePinner parse(String specification) {
        Set<String> pins = new LinkedHashSet<>();
        if (specification != null) {
            for (String entry : specification.split("[,;]")) {
                String pin = entry.trim();
                if (pin.startsWith(PREFIX) && pin.length() > PREFIX.length()) {
                    pins.add(pin);
                }
                // Anything else is ignored rather than fatal. A malformed pin must not stop the
                // agent starting, and it cannot weaken anything: an unparsed pin is simply
                // absent, and an empty pin set means normal TLS.
            }
        }
        return new CertificatePinner(pins);
    }

    public boolean isEnabled() {
        return !pins.isEmpty();
    }

    /** @return a factory enforcing these pins, or null when there is nothing to enforce */
    public SSLSocketFactory socketFactory() {
        if (!isEnabled()) {
            return null;
        }
        try {
            X509ExtendedTrustManager platform = platformTrustManager();
            if (platform == null) {
                return null;
            }
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[] {new PinningTrustManager(platform, pins)}, null);
            return context.getSocketFactory();
        } catch (Exception e) {
            // Failing to build the pinned context must not silently downgrade to unpinned TLS.
            // Returning null makes the caller refuse to send, which is the safe direction.
            return null;
        }
    }

    /**
     * Whether any certificate in the chain matches a configured pin.
     *
     * <p>The decision the trust manager makes, exposed so it can be tested against real
     * certificates without standing up a TLS endpoint. An empty pin set matches everything,
     * because pinning is then switched off.
     */
    boolean matches(X509Certificate[] chain) throws CertificateException {
        if (!isEnabled()) {
            return true;
        }
        if (chain == null || chain.length == 0) {
            return false;
        }
        for (X509Certificate certificate : chain) {
            if (pins.contains(pinFor(certificate))) {
                return true;
            }
        }
        return false;
    }

    /** The SHA-256 SubjectPublicKeyInfo pin for a certificate, in the configured format. */
    public static String pinFor(X509Certificate certificate) throws CertificateException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return PREFIX
                    + Base64.getEncoder()
                            .encodeToString(digest.digest(certificate.getPublicKey().getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            throw new CertificateException("SHA-256 unavailable", e);
        }
    }

    private static X509ExtendedTrustManager platformTrustManager() throws Exception {
        TrustManagerFactory factory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init((KeyStore) null);
        for (TrustManager manager : factory.getTrustManagers()) {
            if (manager instanceof X509ExtendedTrustManager extended) {
                return extended;
            }
        }
        return null;
    }

    /**
     * Delegates to the platform, then enforces the pin.
     *
     * <p>Extends {@code X509ExtendedTrustManager} rather than the plain interface so the
     * socket and engine overloads carrying the peer's identity reach the delegate. Dropping to
     * the two-argument form is the classic way an implementation quietly disables hostname
     * verification.
     */
    private static final class PinningTrustManager extends X509ExtendedTrustManager {

        private final X509ExtendedTrustManager delegate;
        private final Set<String> pins;

        PinningTrustManager(X509ExtendedTrustManager delegate, Set<String> pins) {
            this.delegate = delegate;
            this.pins = pins;
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            delegate.checkServerTrusted(chain, authType, socket);
            enforce(chain);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            delegate.checkServerTrusted(chain, authType, engine);
            enforce(chain);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            delegate.checkServerTrusted(chain, authType);
            enforce(chain);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            delegate.checkClientTrusted(chain, authType, socket);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            delegate.checkClientTrusted(chain, authType, engine);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            delegate.checkClientTrusted(chain, authType);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return delegate.getAcceptedIssuers();
        }

        private void enforce(X509Certificate[] chain) throws CertificateException {
            if (!new CertificatePinner(pins).matches(chain)) {
                // Deliberately terse. Echoing the presented chain into a customer's log helps
                // an attacker inspecting that log more than it helps an operator.
                throw new CertificateException(
                        "aegis: server certificate does not match any configured pin");
            }
        }
    }
}
