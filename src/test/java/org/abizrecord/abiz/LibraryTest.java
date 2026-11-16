package org.abizrecord.abiz;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.HexFormat;
import java.util.Locale;
import java.util.SplittableRandom;
import org.junit.jupiter.api.Test;

/** Checks beyond the shared vectors. */
class LibraryTest {
  private static final byte[] SEED_1 = HexFormat.of().parseHex("edcb87f24a87794d432f17cd60a9a864609ff2592a03108dd2c95c0e28eabc78");

  @Test
  void signRecordRoundTrip() {
    JsonNode cases = Vectors.load("records.json").get("cases");
    JsonNode signed = null;
    String assertion = null;
    for (JsonNode c : cases) {
      if (c.get("name").asText().equals("signed by test key 1")) {
        signed = Abiz.parseJson(c.get("record_text").asText());
        assertion = c.get("assertion").asText();
      }
    }
    ObjectNode copy = ((ObjectNode) signed).deepCopy();
    copy.put("description", "Re-signed by the Java library.");
    copy.remove("signature");
    ObjectNode resigned = Abiz.signRecord(copy, SEED_1);
    assertEquals(signed.get("public_key"), resigned.get("public_key"));
    assertNull(Abiz.checkRecord(resigned.toString(), "harbourbikes.example.org", assertion));
    // Signing the unchanged record again gives the published signature (Ed25519 is deterministic).
    assertEquals(signed.get("signature"), Abiz.signRecord((ObjectNode) signed, SEED_1).get("signature"));
  }

  @Test
  void canonicalizeRefusesDuplicatesAndLoneSurrogates() {
    assertThrows(IllegalArgumentException.class, () -> Abiz.canonicalize("{\"a\":1,\"a\":2}"));
    assertThrows(Jcs.JcsException.class, () -> Abiz.canonicalize("[\"\\ud800\"]"));
  }

  @Test
  void numbersMatchTheShortestRoundTrip() {
    // From Java 19, Double.toString gives the shortest round-trip digits (JDK-4511638), so it can
    // check Jcs.number's own search on many random doubles. Java 17 skips this test.
    assumeTrue(Runtime.version().feature() >= 19);
    SplittableRandom random = new SplittableRandom(8785);
    for (int i = 0; i < 50_000; i++) {
      double value = Double.longBitsToDouble(random.nextLong());
      if (Double.isNaN(value) || Double.isInfinite(value)) continue;
      assertEquals(fromJavaToString(value), Jcs.number(value), () -> "for " + value);
    }
    for (int e = -1074; e <= 1023; e++) {
      double value = Math.scalb(1.0, e);
      assertEquals(fromJavaToString(value), Jcs.number(value), "2^" + e);
    }
  }

  /** ECMAScript formatting applied to the digits of Java 19+'s shortest Double.toString. */
  private static String fromJavaToString(double value) {
    if (value == 0) return "0";
    if (value < 0) return "-" + fromJavaToString(-value);
    java.math.BigDecimal d = new java.math.BigDecimal(Double.toString(value)).stripTrailingZeros();
    // Java always writes at least two significant digits; ECMAScript writes one when one is enough.
    if (d.precision() == 2) {
      for (java.math.RoundingMode mode : new java.math.RoundingMode[] {java.math.RoundingMode.HALF_EVEN,
          java.math.RoundingMode.FLOOR, java.math.RoundingMode.CEILING}) {
        java.math.BigDecimal one = d.round(new java.math.MathContext(1, mode));
        if (one.doubleValue() == value) {
          d = one.stripTrailingZeros();
          break;
        }
      }
    }
    String s = d.unscaledValue().toString();
    int k = s.length();
    int n = k - d.scale();
    if (k <= n && n <= 21) return s + "0".repeat(n - k);
    if (0 < n && n <= 21) return s.substring(0, n) + "." + s.substring(n);
    if (-6 < n && n <= 0) return "0." + "0".repeat(-n) + s;
    int exp = n - 1;
    return s.charAt(0) + (k > 1 ? "." + s.substring(1) : "") + "e" + (exp < 0 ? "-" : "+") + Math.abs(exp);
  }

  @Test
  void ecmaRegexTranslation() {
    assertEquals("^" + Text.JS_SPACE + "\\z", EcmaRegexFactory.translate("^\\s$"));
    assertEquals("[^/" + Text.JS_SPACE_CLASS_BODY + "]", EcmaRegexFactory.translate("[^/\\s]"));
    // \S matches a no-break space neither at the start nor at the end of a value.
    assertEquals(false, EcmaRegexFactory.INSTANCE.getRegularExpression("^\\S(?:.*\\S)?$").matches("\u00a0x"));
    assertEquals(true, EcmaRegexFactory.INSTANCE.getRegularExpression("^\\S(?:.*\\S)?$").matches("x y"));
    assertEquals(false, EcmaRegexFactory.INSTANCE.getRegularExpression("^[A-Z]{2}$").matches("GB\n"));
  }

  @Test
  void errorCodesHaveWireNames() {
    for (ErrorCode code : ErrorCode.values()) {
      assertEquals(code.name().toLowerCase(Locale.ROOT), code.code());
      assertEquals(code, ErrorCode.fromCode(code.code()));
    }
  }
}
