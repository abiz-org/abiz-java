package org.abizrecord.abiz;

/**
 * ECMAScript string helpers. The reference resolver is written in TypeScript, so where it uses
 * {@code \s}, {@code trim()} or {@code $} the Java port must use the ECMAScript meaning, which
 * differs from {@link String#strip()} and {@link java.util.regex.Pattern}'s defaults.
 */
final class Text {
  private Text() {}

  /** ECMAScript {@code \s}: WhiteSpace and LineTerminator code points, as a regex character class body. */
  static final String JS_SPACE_CLASS_BODY =
      "\\t\\n\\x0B\\f\\r \\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000\\uFEFF";

  /** ECMAScript {@code \s} as a character class. */
  static final String JS_SPACE = "[" + JS_SPACE_CLASS_BODY + "]";

  /** True when {@code c} matches ECMAScript {@code \s}. */
  static boolean isJsSpace(char c) {
    switch (c) {
      case '\t': case '\n': case 0x0B: case '\f': case '\r': case ' ':
      case 0x00A0: case 0x1680: case 0x2028: case 0x2029: case 0x202F: case 0x205F: case 0x3000: case 0xFEFF:
        return true;
      default:
        return c >= 0x2000 && c <= 0x200A;
    }
  }

  /** {@code String.prototype.trim}. */
  static String jsTrim(String s) {
    int start = 0;
    int end = s.length();
    while (start < end && isJsSpace(s.charAt(start))) start++;
    while (end > start && isJsSpace(s.charAt(end - 1))) end--;
    return s.substring(start, end);
  }

  /** True when the text holds an unpaired UTF-16 surrogate (not I-JSON). */
  static boolean hasLoneSurrogate(String s) {
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (Character.isHighSurrogate(c)) {
        if (i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
          i++;
        } else {
          return true;
        }
      } else if (Character.isLowSurrogate(c)) {
        return true;
      }
    }
    return false;
  }
}
