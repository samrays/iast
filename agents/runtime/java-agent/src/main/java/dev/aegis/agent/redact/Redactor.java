package dev.aegis.agent.redact;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Removes secrets and personal data <em>before anything leaves the customer's process</em>.
 *
 * <p>This is threat T-04, and it is the control that decides whether the platform is
 * deployable in a regulated environment at all. Redacting server-side would mean the secret
 * has already crossed the network and been written to someone's ingest log.
 *
 * <p>Two independent mechanisms, because either alone leaks:
 *
 * <ul>
 *   <li><b>key deny-list</b> — a parameter or header whose <em>name</em> looks sensitive is
 *       replaced wholesale, whatever its value;
 *   <li><b>value patterns</b> — card numbers and similar shapes are caught even when they
 *       arrive under an innocuous name like {@code q}.
 * </ul>
 */
public final class Redactor {

    public static final String PLACEHOLDER = "[redacted]";

    /** Default deny-list. Tenants may add to it; the control plane may never shrink it. */
    public static final Set<String> DEFAULT_KEYS =
            Set.of(
                    "password",
                    "passwd",
                    "pwd",
                    "secret",
                    "token",
                    "access_token",
                    "refresh_token",
                    "api_key",
                    "apikey",
                    "authorization",
                    "auth",
                    "cookie",
                    "set-cookie",
                    "session",
                    "sessionid",
                    "jsessionid",
                    "csrf",
                    "ssn",
                    "card",
                    "cardnumber",
                    "cvv",
                    "cvc",
                    "pan",
                    "pin",
                    "private_key",
                    "client_secret");

    /** 13–19 digits with optional separators: the shape of a payment card. */
    private static final Pattern CARD =
            Pattern.compile("\\b(?:\\d[ -]?){13,19}\\b");

    /** Three-part dot-separated base64url: a JWT, whatever field it turned up in. */
    private static final Pattern JWT =
            Pattern.compile("\\beyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\b");

    private static final Pattern EMAIL =
            Pattern.compile("\\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\\.[A-Za-z]{2,}\\b");

    /** How much of a value is kept once it passes the key and pattern checks. */
    public enum CaptureMode {
        /** Nothing is captured. The finding still carries the flow; the value is dropped. */
        NONE,
        /** Only a digest, so recurrences can be correlated without storing the value. */
        HASHED,
        TRUNCATED,
        /** Everything, up to the length cap. Sensible in development, rarely in production. */
        FULL
    }

    private final Set<String> deniedKeys;
    private final CaptureMode captureMode;
    private final int maxValueLength;
    private final boolean redactEmails;

    public Redactor(
            Set<String> extraKeys,
            CaptureMode captureMode,
            int maxValueLength,
            boolean redactEmails) {
        Set<String> keys = new LinkedHashSet<>(DEFAULT_KEYS);
        if (extraKeys != null) {
            for (String key : extraKeys) {
                if (key != null && !key.isBlank()) {
                    keys.add(key.toLowerCase(Locale.ROOT));
                }
            }
        }
        this.deniedKeys = Set.copyOf(keys);
        this.captureMode = captureMode;
        this.maxValueLength = Math.max(0, maxValueLength);
        this.redactEmails = redactEmails;
    }

    /** Development-friendly default: truncate to 512 characters, keep email addresses. */
    public static Redactor defaults() {
        return new Redactor(Set.of(), CaptureMode.TRUNCATED, 512, false);
    }

    /**
     * True when a field with this name must never have its value transmitted.
     *
     * <p>Substring matching, not equality: real applications call it {@code user_password},
     * {@code X-Auth-Token} or {@code stripeApiKey}, and an exact-match list would miss all
     * three.
     */
    public boolean isSensitiveKey(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        String lowered = name.toLowerCase(Locale.ROOT);
        for (String denied : deniedKeys) {
            if (lowered.contains(denied)) {
                return true;
            }
        }
        return false;
    }

    /** Redact by field name first, then by value shape. */
    public String redact(String name, String value) {
        if (isSensitiveKey(name)) {
            return PLACEHOLDER;
        }
        return redactValue(value);
    }

    /** Redact a bare value — used for sink arguments, which have no field name. */
    public String redactValue(String value) {
        if (value == null) {
            return "";
        }
        if (captureMode == CaptureMode.NONE) {
            return PLACEHOLDER;
        }
        if (captureMode == CaptureMode.HASHED) {
            return "sha256:" + sha256(value);
        }

        String scrubbed = JWT.matcher(value).replaceAll(PLACEHOLDER);
        scrubbed = CARD.matcher(scrubbed).replaceAll(PLACEHOLDER);
        if (redactEmails) {
            scrubbed = EMAIL.matcher(scrubbed).replaceAll(PLACEHOLDER);
        }

        if (captureMode == CaptureMode.TRUNCATED && scrubbed.length() > maxValueLength) {
            return scrubbed.substring(0, maxValueLength) + "…";
        }
        return scrubbed;
    }

    /** Redact a whole map of parameters or headers in place of the caller. */
    public Map<String, String> redactAll(Map<String, String> values) {
        if (values == null || values.isEmpty()) {
            return Map.of();
        }
        Map<String, String> result = new java.util.LinkedHashMap<>(values.size());
        for (Map.Entry<String, String> entry : values.entrySet()) {
            result.put(entry.getKey(), redact(entry.getKey(), entry.getValue()));
        }
        return result;
    }

    public CaptureMode captureMode() {
        return captureMode;
    }

    private static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of()
                    .formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)))
                    .substring(0, 32);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
