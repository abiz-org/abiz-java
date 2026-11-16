package org.abizrecord.abiz;

import com.networknt.schema.regex.RegularExpression;
import com.networknt.schema.regex.RegularExpressionFactory;
import java.util.regex.Pattern;

/**
 * JSON Schema {@code pattern} keywords are ECMA-262 regular expressions. The schema's patterns use
 * only constructs Java shares with ECMAScript, except three whose meaning differs: {@code \s} and
 * {@code \S} (ECMAScript's include Unicode spaces), {@code .} (ECMAScript's matches U+0085) and
 * {@code $} (ECMAScript's, without the m flag, matches only at the end). This factory translates
 * those three and compiles the rest unchanged.
 */
final class EcmaRegexFactory implements RegularExpressionFactory {
  static final EcmaRegexFactory INSTANCE = new EcmaRegexFactory();

  private EcmaRegexFactory() {}

  @Override
  public RegularExpression getRegularExpression(String regex) {
    Pattern pattern = Pattern.compile(translate(regex));
    return value -> pattern.matcher(value).find();
  }

  static String translate(String regex) {
    StringBuilder out = new StringBuilder();
    boolean inClass = false;
    for (int i = 0; i < regex.length(); i++) {
      char c = regex.charAt(i);
      if (c == '\\' && i + 1 < regex.length()) {
        char next = regex.charAt(++i);
        if (next == 's') {
          out.append(inClass ? Text.JS_SPACE_CLASS_BODY : Text.JS_SPACE);
        } else if (next == 'S') {
          // Inside a class, a nested class is a union in Java: [a[^b]] is "a or not b".
          out.append("[^").append(Text.JS_SPACE_CLASS_BODY).append(']');
        } else {
          out.append(c).append(next);
        }
        continue;
      }
      if (inClass) {
        if (c == ']') inClass = false;
        out.append(c);
        continue;
      }
      switch (c) {
        case '[':
          inClass = true;
          out.append(c);
          if (i + 1 < regex.length() && regex.charAt(i + 1) == '^') {
            out.append('^');
            i++;
          }
          break;
        case '.':
          out.append("[^\\n\\r\\u2028\\u2029]");
          break;
        case '$':
          out.append("\\z");
          break;
        default:
          out.append(c);
      }
    }
    return out.toString();
  }
}
