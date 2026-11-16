package org.abizrecord.abiz;

import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigDecimal;
import java.math.MathContext;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * RFC 8785 JSON Canonicalization Scheme: no whitespace, object members sorted by the UTF-16 code
 * units of their names, ECMAScript string escaping, and ECMAScript number serialisation (every
 * number is read as an IEEE 754 double, as {@code JSON.parse} reads it).
 */
public final class Jcs {
  private Jcs() {}

  /** Thrown for a value RFC 8785 cannot canonicalise (not I-JSON). */
  public static final class JcsException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    JcsException(String message) {
      super(message);
    }
  }

  /**
   * The canonical form of a JSON value.
   *
   * @param value a parsed JSON value
   * @return its RFC 8785 text
   * @throws JcsException for a lone surrogate, NaN or an infinite number
   */
  public static String canonicalize(JsonNode value) {
    StringBuilder out = new StringBuilder();
    write(value, out);
    return out.toString();
  }

  private static void write(JsonNode node, StringBuilder out) {
    if (node == null || node.isNull() || node.isMissingNode()) {
      out.append("null");
    } else if (node.isBoolean()) {
      out.append(node.booleanValue() ? "true" : "false");
    } else if (node.isNumber()) {
      out.append(number(node.doubleValue()));
    } else if (node.isTextual()) {
      string(node.textValue(), out);
    } else if (node.isArray()) {
      out.append('[');
      for (int i = 0; i < node.size(); i++) {
        if (i > 0) out.append(',');
        write(node.get(i), out);
      }
      out.append(']');
    } else if (node.isObject()) {
      List<Map.Entry<String, JsonNode>> entries = new ArrayList<>(node.properties());
      // String.compareTo compares UTF-16 code units, as RFC 8785 section 3.2.3 asks.
      entries.sort(Map.Entry.comparingByKey());
      out.append('{');
      boolean first = true;
      for (Map.Entry<String, JsonNode> entry : entries) {
        if (!first) out.append(',');
        first = false;
        string(entry.getKey(), out);
        out.append(':');
        write(entry.getValue(), out);
      }
      out.append('}');
    } else {
      throw new JcsException("a " + node.getNodeType() + " is not a JSON value");
    }
  }

  /** {@code JSON.stringify} of a string: RFC 8785 section 3.2.2.2. */
  private static void string(String value, StringBuilder out) {
    if (Text.hasLoneSurrogate(value)) throw new JcsException("a string holds a lone surrogate (not I-JSON)");
    out.append('"');
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      switch (c) {
        case '"': out.append("\\\""); break;
        case '\\': out.append("\\\\"); break;
        case '\b': out.append("\\b"); break;
        case '\f': out.append("\\f"); break;
        case '\n': out.append("\\n"); break;
        case '\r': out.append("\\r"); break;
        case '\t': out.append("\\t"); break;
        default:
          if (c < 0x20) {
            out.append("\\u00").append(Character.forDigit(c >> 4, 16)).append(Character.forDigit(c & 0xf, 16));
          } else {
            out.append(c);
          }
      }
    }
    out.append('"');
  }

  /**
   * ECMAScript {@code Number::toString} for a double (ECMA-262 section 6.1.6.1.20), which RFC 8785
   * section 3.2.2.3 adopts. The shortest digit string that reads back as the same double is found
   * with {@link BigDecimal}, so the result does not depend on the JDK's {@link Double#toString}.
   *
   * @param value a finite double
   * @return its ECMAScript text; {@code -0} is written {@code 0}
   * @throws JcsException for NaN or an infinite value
   */
  public static String number(double value) {
    if (Double.isNaN(value) || Double.isInfinite(value)) throw new JcsException("a number is NaN or infinite (not I-JSON)");
    if (value == 0) return "0";
    if (value < 0) return "-" + number(-value);
    BigDecimal exact = new BigDecimal(value);
    BigDecimal shortest = null;
    for (int precision = 1; precision <= 17; precision++) {
      BigDecimal candidate = exact.round(new MathContext(precision, RoundingMode.HALF_EVEN));
      if (candidate.doubleValue() == value) {
        shortest = candidate;
        break;
      }
      // At a power of two the rounding interval is lopsided: a p-digit neighbour on the wide side
      // may read back as the value while the nearest one does not.
      for (RoundingMode mode : new RoundingMode[] {RoundingMode.FLOOR, RoundingMode.CEILING}) {
        BigDecimal other = exact.round(new MathContext(precision, mode));
        if (other.doubleValue() == value) {
          shortest = other;
          break;
        }
      }
      if (shortest != null) break;
    }
    if (shortest == null) shortest = exact.round(new MathContext(17, RoundingMode.HALF_EVEN));
    shortest = shortest.stripTrailingZeros();
    String s = shortest.unscaledValue().toString();
    int k = s.length();
    int n = k - shortest.scale(); // value = s x 10^(n - k)
    StringBuilder out = new StringBuilder();
    if (k <= n && n <= 21) {
      out.append(s);
      for (int i = 0; i < n - k; i++) out.append('0');
    } else if (0 < n && n <= 21) {
      out.append(s, 0, n).append('.').append(s, n, k);
    } else if (-6 < n && n <= 0) {
      out.append("0.");
      for (int i = 0; i < -n; i++) out.append('0');
      out.append(s);
    } else {
      int e = n - 1;
      out.append(s.charAt(0));
      if (k > 1) out.append('.').append(s, 1, k);
      out.append('e').append(e < 0 ? '-' : '+').append(Math.abs(e));
    }
    return out.toString();
  }
}
