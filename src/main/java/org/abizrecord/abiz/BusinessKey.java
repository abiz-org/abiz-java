package org.abizrecord.abiz;

import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The ABIZ 1.1 business key (SPEC section 4.2): {@code country "-" [subdivision "-"] number}, used
 * as the DNS {@code k} tag and the record's {@code business_key}. Canonical form: lower-case country
 * and subdivision, upper-case number ({@code us-or-123456}, {@code gb-SC123456}).
 *
 * @param country the lower-case ISO 3166-1 alpha-2 country
 * @param subdivision the lower-case subdivision, or null
 * @param number the upper-case registration number
 */
public record BusinessKey(String country, String subdivision, String number) {
  /** The longest business key, in characters. */
  public static final int MAX_LENGTH = 128;

  private static final Pattern REG_NUMBER = Pattern.compile("^[A-Za-z0-9]+\\z");
  private static final Pattern SUBDIVISION = Pattern.compile("^[A-Za-z0-9]{1,3}\\z");
  /** SPEC section 4.2.2. {@code provincial}: required, except for a federal key. */
  private static final Map<String, String> SUBDIVISION_RULE = Map.of("us", "required", "ae", "required", "ca", "provincial");
  /** SPEC section 4.2.7: assigned, but ABIZ does not support a business there. */
  private static final Set<String> UNSUPPORTED = Set.of("kp");

  /** The canonical text, for example {@code us-or-123456}. */
  public String canonical() {
    return subdivision == null ? country + "-" + number : country + "-" + subdivision + "-" + number;
  }

  /**
   * The outcome of parsing a business key.
   *
   * @param key the key, when it parses
   * @param message why it does not, otherwise
   */
  public record Parsed(BusinessKey key, String message) {
    /** True when {@link #key()} is set. */
    public boolean ok() {
      return key != null;
    }
  }

  /**
   * Parse a business key under SPEC sections 4.2.1 and 4.2.2.
   *
   * @param value the key as published
   * @return the key or the reason it is not one
   */
  public static Parsed parse(String value) {
    if (value.length() > MAX_LENGTH) return fail("A business key is at most " + MAX_LENGTH + " characters.");
    String[] parts = value.split("-", -1);
    if (parts.length != 2 && parts.length != 3) {
      return fail("A business key is country-number or country-subdivision-number, for example gb-01234567 or us-or-123456.");
    }
    String rawCountry = parts[0];
    String rawSub = parts.length == 3 ? parts[1] : null;
    String rawNumber = parts[parts.length - 1];
    if (!Iso3166.isAssignedCountry(rawCountry)) {
      return fail("\"" + clip(rawCountry, 8) + "\" is not an assigned ISO 3166-1 alpha-2 country code (the United Kingdom is gb).");
    }
    String unsupported = countrySupportProblem(rawCountry);
    if (unsupported != null) return fail(unsupported);
    String country = rawCountry.toLowerCase(Locale.ROOT);
    if (!REG_NUMBER.matcher(rawNumber).matches()) {
      return fail("The registration number in a business key must be ASCII letters and digits only.");
    }
    String rule = SUBDIVISION_RULE.get(country);
    String subdivision = null;
    if (rawSub == null) {
      if ("required".equals(rule)) return fail("A business key for " + country + " must include the subdivision.");
    } else {
      if (!SUBDIVISION.matcher(rawSub).matches()) return fail("A business key subdivision is 1 to 3 ASCII letters or digits.");
      if (rule == null) return fail("A business key for " + country + " must not include a subdivision.");
      subdivision = rawSub.toLowerCase(Locale.ROOT);
      Set<String> known = Iso3166.SUBDIVISIONS.get(country);
      if (known == null || !known.contains(subdivision)) {
        return fail(country + "-" + subdivision + " is not a permitted ISO 3166-2 subdivision for a business key.");
      }
    }
    return new Parsed(new BusinessKey(country, subdivision, rawNumber.toUpperCase(Locale.ROOT)), null);
  }

  /**
   * Two business keys are the same key when they match ignoring ASCII case (SPEC section 4.2.4).
   *
   * @param a one key
   * @param b another key
   * @return whether they name the same business
   */
  public static boolean same(String a, String b) {
    return a.toLowerCase(Locale.ROOT).equals(b.toLowerCase(Locale.ROOT));
  }

  /** SPEC section 4.2.7: {@code kp} is assigned and still not a valid ABIZ country. */
  static String countrySupportProblem(String code) {
    if (!UNSUPPORTED.contains(code.toLowerCase(Locale.ROOT))) return null;
    return "\"" + code + "\" is not supported by ABIZ (SPEC section 4.2.7).";
  }

  /** An ISO 3166-2 region code against its country (SPEC section 4.7.13). */
  static String regionCodeProblem(String code, String country) {
    int dash = code.indexOf('-');
    String prefix = dash == -1 ? code : code.substring(0, dash);
    String sub = dash == -1 ? "" : code.substring(dash + 1);
    if (!prefix.toLowerCase(Locale.ROOT).equals(country.toLowerCase(Locale.ROOT))) {
      return "region code \"" + code + "\" does not belong to country \"" + country + "\".";
    }
    Set<String> known = Iso3166.SUBDIVISIONS.get(country.toLowerCase(Locale.ROOT));
    if (known != null && !known.contains(sub.toLowerCase(Locale.ROOT))) {
      return "region code \"" + code + "\" is not an assigned ISO 3166-2 code.";
    }
    return null;
  }

  private static Parsed fail(String message) {
    return new Parsed(null, message);
  }

  private static String clip(String s, int n) {
    return s.length() > n ? s.substring(0, n) : s;
  }
}
