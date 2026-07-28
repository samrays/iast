package dev.aegis.agent.detect;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.aegis.agent.redact.Redactor;
import dev.aegis.agent.taint.RuleClass;
import dev.aegis.agent.taint.SourceKind;
import dev.aegis.agent.taint.TaintedValue;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class DetectionTest {

    private final SinkDetector detector =
            new SinkDetector(Redactor.defaults(), Set.of("com.acme."));

    private static StackTraceElement[] stack(String... classes) {
        StackTraceElement[] frames = new StackTraceElement[classes.length];
        for (int i = 0; i < classes.length; i++) {
            frames[i] = new StackTraceElement(classes[i], "handle", classes[i] + ".java", 40 + i);
        }
        return frames;
    }

    @Nested
    @DisplayName("sink evaluation")
    class Evaluation {

        @Test
        void reportsAConcatenatedQuery() {
            String prefix = "SELECT * FROM users WHERE name = '";
            String payload = "' OR 1=1--";
            String sql = prefix + payload + "'";

            TaintedValue taint =
                    TaintedValue.concat(
                            TaintedValue.empty(),
                            prefix.length(),
                            TaintedValue.fullyTainted(payload.length(), SourceKind.PARAMETER, "name"));

            Finding finding =
                    detector.evaluate(
                            taint,
                            sql,
                            RuleClass.SQL_INJECTION,
                            "java.sql.Statement#executeQuery(String)",
                            stack("com.acme.UserRepository", "com.acme.UserController"),
                            false);

            assertNotNull(finding);
            assertEquals(Finding.Confidence.CONFIRMED, finding.confidence());
            assertEquals(RuleClass.Severity.CRITICAL, finding.effectiveSeverity());
            assertEquals(1, finding.ranges().size());
            assertEquals(prefix.length(), finding.ranges().get(0).start());
        }

        @Test
        void staysSilentWhenTheValueWasBound() {
            // What a PreparedStatement does: the value is still tainted, but not for SQL.
            TaintedValue bound =
                    TaintedValue.fullyTainted(10, SourceKind.PARAMETER, "name")
                            .sanitizedFor(RuleClass.SQL_INJECTION);

            Finding finding =
                    detector.evaluate(
                            bound,
                            "' OR 1=1--",
                            RuleClass.SQL_INJECTION,
                            "java.sql.PreparedStatement#execute()",
                            stack("com.acme.UserRepository"),
                            false);

            // The single most important negative case in the product.
            assertNull(finding);
        }

        @Test
        void escapingForOneRuleDoesNotProtectAnother() {
            TaintedValue htmlSafe =
                    TaintedValue.fullyTainted(12, SourceKind.PARAMETER, "q")
                            .sanitizedFor(RuleClass.REFLECTED_XSS);

            Finding finding =
                    detector.evaluate(
                            htmlSafe,
                            "; rm -rf /",
                            RuleClass.COMMAND_INJECTION,
                            "java.lang.Runtime#exec(String)",
                            stack("com.acme.Ops"),
                            false);

            assertNotNull(finding);
            assertEquals(Finding.Confidence.CONFIRMED, finding.confidence());
        }

        @Test
        void promotesToExploitedWhenThePayloadMatchesASignature() {
            TaintedValue taint =
                    TaintedValue.fullyTainted(10, SourceKind.PARAMETER, "name");

            Finding finding =
                    detector.evaluate(
                            taint,
                            "' OR 1=1--",
                            RuleClass.SQL_INJECTION,
                            "java.sql.Statement#executeQuery(String)",
                            stack("com.acme.UserRepository"),
                            true);

            assertEquals(Finding.Confidence.EXPLOITED, finding.confidence());
        }

        @Test
        void ignoresUntaintedArguments() {
            assertNull(
                    detector.evaluate(
                            TaintedValue.empty(),
                            "SELECT 1",
                            RuleClass.SQL_INJECTION,
                            "java.sql.Statement#executeQuery(String)",
                            stack("com.acme.Repo"),
                            false));
        }

        @Test
        void redactsTheCapturedArgument() {
            SinkDetector strict =
                    new SinkDetector(
                            new Redactor(Set.of(), Redactor.CaptureMode.NONE, 0, false),
                            Set.of("com.acme."));

            Finding finding =
                    strict.evaluate(
                            TaintedValue.fullyTainted(6, SourceKind.PARAMETER, "q"),
                            "secret-value",
                            RuleClass.SQL_INJECTION,
                            "java.sql.Statement#executeQuery(String)",
                            stack("com.acme.Repo"),
                            false);

            assertEquals(Redactor.PLACEHOLDER, finding.sinkArgument());
        }
    }

    @Nested
    @DisplayName("finding identity")
    class Identity {

        @Test
        void ignoresLineNumbers() {
            StackTraceElement[] before = {
                new StackTraceElement("com.acme.Repo", "find", "Repo.java", 40)
            };
            StackTraceElement[] after = {
                new StackTraceElement("com.acme.Repo", "find", "Repo.java", 187)
            };

            // A reformat must not resurrect every closed finding.
            assertEquals(
                    fingerprintFor(before), fingerprintFor(after), "line numbers must not matter");
        }

        @Test
        void ignoresFrameworkFrames() {
            StackTraceElement[] springFive = {
                new StackTraceElement("com.acme.Repo", "find", "Repo.java", 40),
                new StackTraceElement("org.springframework.web.Old", "invoke", "Old.java", 1)
            };
            StackTraceElement[] springSix = {
                new StackTraceElement("com.acme.Repo", "find", "Repo.java", 40),
                new StackTraceElement("org.springframework.web.New", "invoke", "New.java", 9)
            };

            // A dependency bump is not a new vulnerability.
            assertEquals(fingerprintFor(springFive), fingerprintFor(springSix));
        }

        @Test
        void distinguishesDifferentCallPaths() {
            assertNotEquals(
                    fingerprintFor(stack("com.acme.UserRepo")),
                    fingerprintFor(stack("com.acme.OrderRepo")));
        }

        private String fingerprintFor(StackTraceElement[] frames) {
            Finding finding =
                    detector.evaluate(
                            TaintedValue.fullyTainted(5, SourceKind.PARAMETER, "q"),
                            "value",
                            RuleClass.SQL_INJECTION,
                            "java.sql.Statement#executeQuery(String)",
                            frames,
                            false);
            return finding.stackFingerprint();
        }
    }

    @Nested
    @DisplayName("application code classification")
    class Classification {

        @Test
        void treatsCustomerPackagesAsApplicationCode() {
            assertTrue(detector.isApplicationCode("com.acme.UserService"));
        }

        @Test
        void treatsJdkAndFrameworksAsNotApplicationCode() {
            assertFalse(detector.isApplicationCode("java.sql.Statement"));
            assertFalse(detector.isApplicationCode("org.springframework.web.Handler"));
            assertFalse(detector.isApplicationCode("dev.aegis.agent.detect.SinkDetector"));
        }

        @Test
        void anExplicitAllowListBeatsTheFrameworkPrefixes() {
            SinkDetector custom = new SinkDetector(Redactor.defaults(), Set.of("org.apache.acme."));
            // A customer whose code lives under org.apache.* would otherwise lose every frame
            // and see all their findings collapse into a single identity.
            assertTrue(custom.isApplicationCode("org.apache.acme.Service"));
            assertFalse(custom.isApplicationCode("org.apache.commons.Lang"));
        }
    }

    @Nested
    @DisplayName("redaction")
    class Redaction {

        private final Redactor redactor = Redactor.defaults();

        @Test
        void redactsBySensitiveFieldName() {
            assertEquals(Redactor.PLACEHOLDER, redactor.redact("password", "hunter2"));
            assertEquals(Redactor.PLACEHOLDER, redactor.redact("X-Auth-Token", "abc"));
            assertEquals(Redactor.PLACEHOLDER, redactor.redact("user_password", "abc"));
            assertEquals(Redactor.PLACEHOLDER, redactor.redact("stripeApiKey", "sk_live_x"));
        }

        @Test
        void keepsOrdinaryFields() {
            assertEquals("shoes", redactor.redact("q", "shoes"));
        }

        @Test
        void redactsCardNumbersWhateverTheFieldIsCalled() {
            String redacted = redactor.redact("q", "pay 4111 1111 1111 1111 now");
            assertFalse(redacted.contains("4111"));
            assertTrue(redacted.contains(Redactor.PLACEHOLDER));
        }

        @Test
        void redactsBearerTokensFoundInAnyValue() {
            String jwt = "eyJhbGciOi.eyJzdWIiOjEyMzQ1.SflKxwRJSMeKKF2QT4";
            assertFalse(redactor.redact("note", jwt).contains("eyJhbGciOi"));
        }

        @Test
        void hashedModeCorrelatesWithoutStoring() {
            Redactor hashed = new Redactor(Set.of(), Redactor.CaptureMode.HASHED, 0, false);
            String first = hashed.redactValue("sensitive");
            String second = hashed.redactValue("sensitive");

            assertTrue(first.startsWith("sha256:"));
            assertEquals(first, second);
            assertNotEquals(first, hashed.redactValue("different"));
        }

        @Test
        void truncatesLongValues() {
            Redactor short_ = new Redactor(Set.of(), Redactor.CaptureMode.TRUNCATED, 8, false);
            assertEquals("abcdefgh…", short_.redactValue("abcdefghijklmnop"));
        }

        @Test
        void tenantKeysAddToTheDefaultsAndNeverReplaceThem() {
            Redactor custom =
                    new Redactor(Set.of("internal_id"), Redactor.CaptureMode.TRUNCATED, 512, false);

            assertEquals(Redactor.PLACEHOLDER, custom.redact("internal_id", "42"));
            // The built-in deny-list must survive: the control plane may narrow capture,
            // never widen it (threat T-04).
            assertEquals(Redactor.PLACEHOLDER, custom.redact("password", "hunter2"));
        }

        @Test
        void emailRedactionIsOptional() {
            Redactor pii = new Redactor(Set.of(), Redactor.CaptureMode.TRUNCATED, 512, true);
            assertFalse(pii.redactValue("mail ada@example.com").contains("ada@example.com"));
            assertTrue(redactor.redactValue("mail ada@example.com").contains("ada@example.com"));
        }
    }
}
