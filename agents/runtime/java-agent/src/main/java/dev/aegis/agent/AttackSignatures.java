package dev.aegis.agent;

import dev.aegis.agent.taint.RuleClass;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Cheap payload classification, used only to promote an already-confirmed dataflow from
 * {@code CONFIRMED} to {@code EXPLOITED}.
 *
 * <p>These patterns never create a finding on their own. That is the difference between this
 * product and a WAF: a signature match at the source proves someone tried something, while a
 * signature match on a value that <em>also</em> reached a sink proves it worked. Blocking
 * mode triggers on the latter only (docs/02 §4.3).
 */
final class AttackSignatures {

    private static final Pattern SQL =
            Pattern.compile(
                    "('\\s*(or|and)\\s*'?\\d|\\bunion\\s+select\\b|--\\s*$|;\\s*drop\\s+table|\\bor\\s+1\\s*=\\s*1\\b)",
                    Pattern.CASE_INSENSITIVE);

    private static final Pattern COMMAND =
            Pattern.compile("([;&|`]|\\$\\(|\\bnc\\b|\\bcurl\\b|\\bwget\\b|/bin/(ba)?sh)");

    private static final Pattern TRAVERSAL =
            Pattern.compile("(\\.\\./|\\.\\.\\\\|%2e%2e[/\\\\])", Pattern.CASE_INSENSITIVE);

    private static final Pattern XSS =
            Pattern.compile(
                    "(<script\\b|javascript:|onerror\\s*=|onload\\s*=|<img\\b[^>]*\\bon)",
                    Pattern.CASE_INSENSITIVE);

    private AttackSignatures() {}

    static boolean looksMalicious(String value, RuleClass rule) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        // Bounded work on the request path: a megabyte body must not turn into a megabyte of
        // regex backtracking inside someone's request.
        String candidate =
                value.length() > 4096 ? value.substring(0, 4096) : value;

        return switch (rule) {
            case SQL_INJECTION -> SQL.matcher(candidate).find();
            case COMMAND_INJECTION -> COMMAND.matcher(candidate).find();
            case PATH_TRAVERSAL -> TRAVERSAL.matcher(candidate).find();
            case REFLECTED_XSS -> XSS.matcher(candidate).find();
            case SSRF -> candidate.toLowerCase(Locale.ROOT).contains("169.254.169.254");
            default -> false;
        };
    }
}
