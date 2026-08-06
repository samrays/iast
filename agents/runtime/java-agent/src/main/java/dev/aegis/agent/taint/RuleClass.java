package dev.aegis.agent.taint;

/**
 * A family of vulnerability that a given sanitizer neutralizes.
 *
 * <p>Sanitization is per rule class, never global. HTML-encoding a value makes it safe to
 * render and does nothing whatsoever to make it safe to concatenate into SQL — an engine
 * that treats "sanitized" as a single flag will happily miss that injection.
 */
public enum RuleClass {
    SQL_INJECTION("sql-injection", Severity.CRITICAL),
    COMMAND_INJECTION("command-injection", Severity.CRITICAL),
    PATH_TRAVERSAL("path-traversal", Severity.HIGH),
    UNSAFE_DESERIALIZATION("unsafe-deserialization", Severity.CRITICAL),
    XXE("xxe", Severity.CRITICAL),
    REFLECTED_XSS("reflected-xss", Severity.HIGH),
    SSRF("ssrf", Severity.HIGH),
    LDAP_INJECTION("ldap-injection", Severity.HIGH),
    XPATH_INJECTION("xpath-injection", Severity.HIGH),
    OPEN_REDIRECT("open-redirect", Severity.MEDIUM),
    LOG_INJECTION("log-injection", Severity.MEDIUM),
    HEADER_INJECTION("header-injection", Severity.MEDIUM);

    private final String key;
    private final Severity severity;

    RuleClass(String key, Severity severity) {
        this.key = key;
        this.severity = severity;
    }

    /** Stable identifier used on the wire and in the rule catalogue. */
    public String key() {
        return key;
    }

    public Severity severity() {
        return severity;
    }

    public enum Severity {
        INFO,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL;

        public String wireName() {
            return "SEVERITY_" + name();
        }
    }
}
