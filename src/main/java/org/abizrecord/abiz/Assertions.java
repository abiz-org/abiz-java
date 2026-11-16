package org.abizrecord.abiz;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The {@code _abiz} TXT assertion (SPEC sections 3.1 to 3.3, ABIZ 1.1): which values count, the
 * DKIM-style tag list, and the {@code h}, {@code k} and {@code p} tags. A port of {@code txt.ts}.
 */
public final class Assertions {
  private Assertions() {}

  private static final Pattern IS_ASSERTION = Pattern.compile("^[ \\t]*v[ \\t]*=[ \\t]*abiz1[ \\t]*(?:;|\\z)");
  private static final Pattern NEAR_MISS =
      Pattern.compile("^" + Text.JS_SPACE + "*\"?" + Text.JS_SPACE + "*v" + Text.JS_SPACE + "*=" + Text.JS_SPACE + "*abiz",
          Pattern.CASE_INSENSITIVE);
  /** Controls other than HTAB, DEL, and any ECMAScript space other than SP and HTAB. */
  private static final Pattern FORBIDDEN =
      Pattern.compile("[\\x00-\\x08\\x0A-\\x1F\\x7F]|(?![ \\t])" + Text.JS_SPACE);
  private static final Pattern TAG_NAME =
      Pattern.compile("^[^" + Text.JS_SPACE_CLASS_BODY + ";=\\x00-\\x1F\\x7F]+\\z");
  private static final Pattern TAG_VALUE =
      Pattern.compile("^[^" + Text.JS_SPACE_CLASS_BODY + ";\\x00-\\x1F\\x7F]+\\z");
  private static final Pattern STD_BASE64_KEY = Pattern.compile("^[A-Za-z0-9+/]{43}=\\z");
  private static final Set<String> RECOGNISED = Set.of("v", "h", "k", "p");

  /**
   * True when the value's first tag is exactly {@code v=abiz1}, so it counts towards the one-record
   * rule. {@code V=ABIZ1}, {@code v=abiz1x} and {@code h=...;v=abiz1} do not count.
   *
   * @param value one TXT value, its character-strings joined
   * @return whether it is an ABIZ assertion
   */
  public static boolean isAssertion(String value) {
    return IS_ASSERTION.matcher(value).find();
  }

  /**
   * True when the value looks like an attempt at an assertion but its first tag is not exactly
   * {@code v=abiz1} (for example {@code V=ABIZ1} or {@code v=abiz2}).
   *
   * @param value one TXT value
   * @return whether it is a near miss
   */
  public static boolean isNearMiss(String value) {
    return !isAssertion(value) && NEAR_MISS.matcher(value).find();
  }

  /**
   * True when the value is an ABIZ 1.1 {@code p} key (SPEC section 3.3.2): 44 characters of
   * canonical standard base64 ending in one {@code =}, decoding to 32 bytes.
   *
   * @param value a {@code p} tag or record {@code public_key}
   * @return whether it is a canonical key
   */
  public static boolean isPublicKey(String value) {
    if (value == null || !STD_BASE64_KEY.matcher(value).matches()) return false;
    byte[] bytes;
    try {
      bytes = Base64.getDecoder().decode(value);
    } catch (IllegalArgumentException e) {
      return false;
    }
    return bytes.length == 32 && Base64.getEncoder().encodeToString(bytes).equals(value);
  }

  /**
   * Parse one {@code v=abiz1} value under ABIZ 1.1: optional SP/HTAB around {@code ;} and {@code =},
   * at most one trailing {@code ;}, {@code v=abiz1} first, recognised tags ({@code v h k p},
   * case-sensitive) at most once, unknown tags ignored, {@code h} required and a safe host with an
   * optional path, {@code k} a business key, {@code p} required and an Ed25519 key.
   *
   * @param value one TXT value
   * @return the assertion, or the error code and message
   */
  public static AssertionResult parse(String value) {
    if (FORBIDDEN.matcher(value).find()) {
      return AssertionResult.fail(ErrorCode.BAD_POINTER,
          "The ABIZ TXT value contains a line break, control character or non-ASCII space. Only spaces and tabs are allowed, and only around \";\" and \"=\".");
    }
    String body = trimWsp(value);
    if (body.endsWith(";")) body = trimWsp(body.substring(0, body.length() - 1));
    List<String[]> tags = new ArrayList<>();
    for (String raw : body.split(";", -1)) {
      String part = trimWsp(raw);
      int eq = part.indexOf('=');
      if (eq <= 0) {
        return AssertionResult.fail(ErrorCode.BAD_POINTER,
            "Every tag must be name=value (found \"" + clip(part) + "\"). An empty tag (\";;\") or more than one trailing \";\" is invalid.");
      }
      String name = trimWsp(part.substring(0, eq));
      String val = trimWsp(part.substring(eq + 1));
      if (!TAG_NAME.matcher(name).matches() || val.isEmpty()) {
        return AssertionResult.fail(ErrorCode.BAD_POINTER,
            "Every tag must be name=value with both parts present (found \"" + clip(part) + "\").");
      }
      if (!TAG_VALUE.matcher(val).matches()) {
        return AssertionResult.fail(ErrorCode.BAD_POINTER,
            "A tag value must not contain whitespace (found \"" + clip(part) + "\"). Spaces are allowed only around \";\" and \"=\".");
      }
      tags.add(new String[] {name, val});
    }
    if (tags.isEmpty() || !tags.get(0)[0].equals("v") || !tags.get(0)[1].equals("abiz1")) {
      return AssertionResult.fail(ErrorCode.BAD_POINTER, "The first tag must be v=abiz1.");
    }
    Map<String, String> seen = new HashMap<>();
    Map<String, String> unknown = new LinkedHashMap<>();
    for (String[] tag : tags) {
      if (RECOGNISED.contains(tag[0])) {
        if (seen.containsKey(tag[0])) {
          return AssertionResult.fail(ErrorCode.DUPLICATE_TAG, "The tag " + tag[0] + "= appears more than once.");
        }
        seen.put(tag[0], tag[1]);
      } else {
        unknown.putIfAbsent(tag[0], tag[1]);
      }
    }
    String rawH = seen.get("h");
    if (rawH == null || rawH.isEmpty()) {
      return AssertionResult.fail(ErrorCode.MISSING_H, "The ABIZ TXT value has no h= tag naming the record host.");
    }
    String h = Hosts.identityParts(rawH);
    if (h == null) {
      return AssertionResult.fail(ErrorCode.BAD_POINTER,
          "h= must be a host name with an optional path: no scheme, port, user name, query, fragment or \".\" segments.");
    }
    if (Hosts.isNonPublicHost(Hosts.identityHostname(h))) {
      return AssertionResult.fail(ErrorCode.UNSAFE_HOST, "h= names a special-use or private-network host.");
    }
    String k = seen.get("k");
    if (k != null) {
      BusinessKey.Parsed key = BusinessKey.parse(k);
      if (!key.ok()) return AssertionResult.fail(ErrorCode.BAD_POINTER, "k= is not an ABIZ 1.1 business key: " + key.message());
    }
    String p = seen.get("p");
    if (p == null) {
      return AssertionResult.fail(ErrorCode.INVALID_KEY,
          "The ABIZ TXT value has no p= tag. p is required (SPEC section 3.3.1): publish p= with the business's Ed25519 public key, 44 characters of standard base64 ending in one \"=\".");
    }
    if (!isPublicKey(p)) {
      return AssertionResult.fail(ErrorCode.INVALID_KEY,
          "p= must be an Ed25519 public key: 44 characters of standard base64 ending in one \"=\", decoding to 32 bytes (SPEC section 3.3.2). Hex strings and base64url values are not accepted.");
    }
    return AssertionResult.of(new Assertion(h, k, p, unknown));
  }

  private static String trimWsp(String s) {
    int start = 0;
    int end = s.length();
    while (start < end && (s.charAt(start) == ' ' || s.charAt(start) == '\t')) start++;
    while (end > start && (s.charAt(end - 1) == ' ' || s.charAt(end - 1) == '\t')) end--;
    return s.substring(start, end);
  }

  private static String clip(String value) {
    return value.length() > 40 ? value.substring(0, 40) + "…" : value;
  }
}
