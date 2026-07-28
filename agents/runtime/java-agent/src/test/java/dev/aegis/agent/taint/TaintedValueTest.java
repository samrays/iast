package dev.aegis.agent.taint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * The range algebra is the heart of the product. If it drifts, the agent either floods users
 * with false positives or silently misses injections — so it is tested harder than anything
 * else in the codebase, including with randomised round-trips.
 */
class TaintedValueTest {

    private static TaintedValue param(int length, String name) {
        return TaintedValue.fullyTainted(length, SourceKind.PARAMETER, name);
    }

    @Nested
    @DisplayName("concatenation")
    class Concatenation {

        @Test
        void shiftsTheRightOperandByTheLeftLength() {
            // "SELECT * FROM users WHERE name = '" + q
            String prefix = "SELECT * FROM users WHERE name = '";
            TaintedValue result = TaintedValue.concat(TaintedValue.empty(), prefix.length(), param(5, "q"));

            assertEquals(1, result.rangeCount());
            TaintRange range = result.ranges().get(0);
            assertEquals(prefix.length(), range.start());
            assertEquals(5, range.length());
        }

        @Test
        void keepsBothOperandsTaint() {
            TaintedValue left = param(4, "a");
            TaintedValue right = param(3, "b");
            TaintedValue result = TaintedValue.concat(left, 4, right);

            assertEquals(2, result.rangeCount());
            assertEquals(0, result.ranges().get(0).start());
            assertEquals(4, result.ranges().get(1).start());
        }

        @Test
        void mergesAdjacentRangesFromTheSameSource() {
            TaintedValue left = param(4, "q");
            TaintedValue right = param(3, "q");
            TaintedValue result = TaintedValue.concat(left, 4, right);

            // Same source and name, touching — one range, not two.
            assertEquals(1, result.rangeCount());
            assertEquals(0, result.ranges().get(0).start());
            assertEquals(7, result.ranges().get(0).length());
        }

        @Test
        void doesNotMergeRangesFromDifferentSources() {
            TaintedValue left = param(4, "q");
            TaintedValue right = TaintedValue.fullyTainted(3, SourceKind.HEADER, "x-user");
            TaintedValue result = TaintedValue.concat(left, 4, right);

            // Merging these would attribute a header's taint to a parameter in the evidence.
            assertEquals(2, result.rangeCount());
        }

        @Test
        void untaintedOperandsProduceNothing() {
            assertFalse(
                    TaintedValue.concat(TaintedValue.empty(), 10, TaintedValue.empty()).isTainted());
        }
    }

    @Nested
    @DisplayName("substring")
    class Substring {

        @Test
        void clipsAndRebases() {
            // 10 chars tainted from 0; take [4, 8)
            TaintedValue result = param(10, "q").substring(4, 8);

            assertEquals(1, result.rangeCount());
            assertEquals(0, result.ranges().get(0).start());
            assertEquals(4, result.ranges().get(0).length());
        }

        @Test
        void dropsRangesOutsideTheWindow() {
            TaintedValue value = TaintedValue.concat(TaintedValue.empty(), 10, param(5, "q"));
            assertFalse(value.substring(0, 5).isTainted());
        }

        @Test
        void keepsThePartialOverlap() {
            TaintedValue value = TaintedValue.concat(TaintedValue.empty(), 10, param(5, "q"));
            TaintedValue clipped = value.substring(8, 12);

            assertEquals(1, clipped.rangeCount());
            assertEquals(2, clipped.ranges().get(0).start());
            assertEquals(2, clipped.ranges().get(0).length());
        }

        @Test
        void emptyWindowYieldsNothing() {
            assertFalse(param(10, "q").substring(5, 5).isTainted());
        }
    }

    @Nested
    @DisplayName("insert")
    class Insert {

        @Test
        void shiftsRangesAfterTheInsertionPoint() {
            TaintedValue value = TaintedValue.concat(TaintedValue.empty(), 10, param(5, "q"));
            TaintedValue result = value.insert(0, TaintedValue.empty(), 3);

            assertEquals(13, result.ranges().get(0).start());
        }

        @Test
        void splitsARangeTheInsertionLandsInside() {
            TaintedValue value = param(10, "q");
            TaintedValue result = value.insert(4, TaintedValue.empty(), 3);

            // Head [0,4) stays, tail moves to [7,13). Losing the tail would under-report.
            assertEquals(2, result.rangeCount());
            assertEquals(0, result.ranges().get(0).start());
            assertEquals(4, result.ranges().get(0).length());
            assertEquals(7, result.ranges().get(1).start());
            assertEquals(6, result.ranges().get(1).length());
        }

        @Test
        void carriesTheInsertedValuesOwnTaint() {
            TaintedValue result = TaintedValue.empty().insert(5, param(4, "q"), 4);

            assertEquals(1, result.rangeCount());
            assertEquals(5, result.ranges().get(0).start());
            assertEquals(4, result.ranges().get(0).length());
        }
    }

    @Nested
    @DisplayName("sanitization")
    class Sanitization {

        @Test
        void clearsOnlyTheNamedRuleClass() {
            TaintedValue value = param(5, "q").sanitizedFor(RuleClass.SQL_INJECTION);

            assertFalse(value.isDangerousFor(RuleClass.SQL_INJECTION));
            // HTML-encoding does not make a value safe to concatenate into a shell command,
            // and neither does SQL escaping make it safe to render.
            assertTrue(value.isDangerousFor(RuleClass.COMMAND_INJECTION));
        }

        @Test
        void survivesFurtherPropagation() {
            TaintedValue safe = param(5, "q").sanitizedFor(RuleClass.SQL_INJECTION);
            TaintedValue combined = TaintedValue.concat(TaintedValue.empty(), 20, safe);

            assertFalse(combined.isDangerousFor(RuleClass.SQL_INJECTION));
        }

        @Test
        void aSanitizedAndAnUnsanitizedRangeDoNotMerge() {
            TaintedValue safe = param(4, "q").sanitizedFor(RuleClass.SQL_INJECTION);
            TaintedValue raw = param(4, "q");
            TaintedValue combined = TaintedValue.concat(safe, 4, raw);

            // Merging would launder the raw half into "sanitized" — a missed vulnerability.
            assertEquals(2, combined.rangeCount());
            assertTrue(combined.isDangerousFor(RuleClass.SQL_INJECTION));
        }

        @Test
        void stillDangerousWhereTheSanitizedRangeDoesNotCover() {
            TaintedValue safe = param(4, "q").sanitizedFor(RuleClass.SQL_INJECTION);
            TaintedValue raw = param(4, "r");
            TaintedValue combined = TaintedValue.concat(safe, 4, raw);

            assertFalse(combined.isDangerousIn(0, 4, RuleClass.SQL_INJECTION));
            assertTrue(combined.isDangerousIn(4, 8, RuleClass.SQL_INJECTION));
        }
    }

    @Nested
    @DisplayName("bounds")
    class Bounds {

        @Test
        void collapsesBeyondTheRangeCap() {
            List<TaintRange> many = new ArrayList<>();
            for (int i = 0; i < TaintedValue.MAX_RANGES + 20; i++) {
                // Gaps keep them from merging, so the cap is what has to stop the growth.
                many.add(new TaintRange(i * 4, 2, SourceKind.PARAMETER, "q"));
            }
            TaintedValue value = TaintedValue.of(many);

            assertEquals(1, value.rangeCount());
            assertTrue(value.isImprecise());
        }

        @Test
        void collapsingNeverLaundersUnsanitizedTaint() {
            List<TaintRange> many = new ArrayList<>();
            for (int i = 0; i < TaintedValue.MAX_RANGES + 5; i++) {
                TaintRange range = new TaintRange(i * 4, 2, SourceKind.PARAMETER, "q");
                // All but one are sanitized. The collapsed range must stay dangerous.
                many.add(i == 0 ? range : range.clearFor(RuleClass.SQL_INJECTION));
            }
            TaintedValue value = TaintedValue.of(many);

            assertEquals(1, value.rangeCount());
            assertTrue(
                    value.isDangerousFor(RuleClass.SQL_INJECTION),
                    "collapsing must take the intersection of cleared rules, never the union");
        }
    }

    @Nested
    @DisplayName("randomised round-trips")
    class Randomised {

        @Test
        void concatThenSubstringRecoversTheOperand() {
            Random random = new Random(20260728L);
            for (int iteration = 0; iteration < 2_000; iteration++) {
                int prefixLength = random.nextInt(50);
                int taintedLength = 1 + random.nextInt(30);

                TaintedValue combined =
                        TaintedValue.concat(
                                TaintedValue.empty(), prefixLength, param(taintedLength, "q"));
                TaintedValue recovered =
                        combined.substring(prefixLength, prefixLength + taintedLength);

                assertEquals(1, recovered.rangeCount());
                assertEquals(0, recovered.ranges().get(0).start());
                assertEquals(taintedLength, recovered.ranges().get(0).length());
            }
        }

        @Test
        void rangesNeverEscapeTheValueTheyDescribe() {
            Random random = new Random(4711L);
            for (int iteration = 0; iteration < 2_000; iteration++) {
                int prefix = random.nextInt(20);
                int mid = 1 + random.nextInt(20);
                int suffix = random.nextInt(20);
                int total = prefix + mid + suffix;

                TaintedValue value =
                        TaintedValue.concat(TaintedValue.empty(), prefix, param(mid, "q"));
                value = TaintedValue.concat(value, prefix + mid, TaintedValue.empty());

                for (TaintRange range : value.ranges()) {
                    assertTrue(range.start() >= 0, "range starts before the value");
                    assertTrue(range.end() <= total, "range extends past the value");
                }
            }
        }
    }
}
