package org.abizrecord.abiz;

import java.io.ByteArrayOutputStream;
import java.net.IDN;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Host names: the queried domain, a website's host, the {@code h=} record host and the URLs a
 * record carries (SPEC sections 3.2 and 4.7.1, resolver specification section 4 step 1). A port of
 * {@code host.ts} in the reference resolver.
 */
public final class Hosts {
  private Hosts() {}

  private static final Pattern HOST = Pattern.compile("^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\\z");
  private static final Pattern IPV4ISH = Pattern.compile("^[0-9.]+\\z");
  private static final Pattern ALL_DIGITS = Pattern.compile("^[0-9]+\\z");
  private static final Pattern HEX_NUMBER = Pattern.compile("^0[xX][0-9A-Fa-f]*\\z");
  private static final Pattern SCHEME = Pattern.compile("^[A-Za-z][A-Za-z0-9+.-]*:");
  private static final Pattern DOMAIN_FORBIDDEN =
      Pattern.compile("[" + Text.JS_SPACE_CLASS_BODY + "/?#@:\\\\%\\[\\]\"'<>`{}|^]");
  private static final Pattern IDENTITY_FORBIDDEN = Pattern.compile("[?#@\\\\" + Text.JS_SPACE_CLASS_BODY + "]");
  private static final Pattern PATH = Pattern.compile("^/[\\x21-\\x7e]*\\z");

  /**
   * Suffixes that never name a public business domain. A query for one is refused before any DNS
   * is sent, and a record host under one is never fetched.
   */
  private static final List<String> NON_PUBLIC_SUFFIXES = List.of(
      "localhost", "local", "internal", "invalid", "test", "example", "onion", "arpa", "alt", "lan", "home",
      "corp", "intranet", "private");

  /**
   * The special-use and private-use names SPEC section 4.7.1 rules out of a record's URLs. The
   * documentation names {@code .example} and {@code .test} stay accepted in a record.
   */
  private static final List<String> SPEC_NON_PUBLIC_SUFFIXES =
      List.of("localhost", "local", "internal", "home.arpa", "onion", "invalid", "alt");

  /**
   * True when the value is a DNS host name as the reference validator accepts it: letters, digits,
   * hyphens and dots, two labels or more, no IP literal. Case and one trailing dot are ignored.
   *
   * @param raw a host name
   * @return whether it is acceptable
   */
  public static boolean isSafeHost(String raw) {
    String value = stripOneDot(raw.toLowerCase(Locale.ROOT));
    if (!HOST.matcher(value).matches() || value.contains("..") || value.length() > 253) return false;
    String[] labels = value.split("\\.", -1);
    if (labels.length < 2) return false;
    for (String label : labels) {
      if (label.isEmpty() || label.length() > 63 || label.startsWith("-") || label.endsWith("-")) return false;
    }
    return !IPV4ISH.matcher(value).matches();
  }

  /**
   * True when the host ends in a special-use or private-network suffix, or an all-digit label.
   *
   * @param host a host name
   * @return whether it is never a public business domain
   */
  public static boolean isNonPublicHost(String host) {
    String[] labels = stripOneDot(host.toLowerCase(Locale.ROOT)).split("\\.", -1);
    String tld = labels[labels.length - 1];
    return NON_PUBLIC_SUFFIXES.contains(tld) || ALL_DIGITS.matcher(tld).matches();
  }

  /**
   * True when the host is a special-use or private-use name under SPEC section 4.7.1.
   *
   * @param host a host name
   * @return whether a record URL may not use it
   */
  public static boolean isSpecialUseName(String host) {
    String name = stripOneDot(host.toLowerCase(Locale.ROOT));
    for (String suffix : SPEC_NON_PUBLIC_SUFFIXES) {
      if (name.equals(suffix) || name.endsWith("." + suffix)) return true;
    }
    return false;
  }

  /**
   * An {@code h=} value or an {@code identity_host}: a host name with an optional path, never a
   * scheme, credentials, port, query or fragment, and no {@code .} or {@code ..} path segment.
   *
   * @param value the value as published
   * @return the canonical form (host lower case, trailing dot dropped, path as written), or null
   */
  public static String identityParts(String value) {
    if (value == null || value.isEmpty() || value.contains("://") || IDENTITY_FORBIDDEN.matcher(value).find()) {
      return null;
    }
    int slash = value.indexOf('/');
    String host = (slash == -1 ? value : value.substring(0, slash)).toLowerCase(Locale.ROOT);
    String path = slash == -1 ? "" : value.substring(slash);
    if (host.contains(":")) return null;
    if (!isSafeHost(host)) return null;
    if (!path.isEmpty()) {
      if (!PATH.matcher(path).matches()) return null;
      for (String segment : path.split("/", -1)) {
        if (segment.equals(".") || segment.equals("..")) return null;
      }
    }
    return stripOneDot(host) + path;
  }

  /**
   * The host part of a canonical identity value.
   *
   * @param identity a value from {@link #identityParts(String)}
   * @return the part before the first slash
   */
  public static String identityHostname(String identity) {
    int slash = identity.indexOf('/');
    return slash == -1 ? identity : identity.substring(0, slash);
  }

  /**
   * The parent of a {@code www.} host, offered as a suggestion only (never resolved in its place).
   *
   * @param domain a normalised domain
   * @return the apex, or null
   */
  public static String apexSuggestion(String domain) {
    if (!domain.startsWith("www.")) return null;
    String rest = domain.substring(4);
    return isSafeHost(rest) ? rest : null;
  }

  /**
   * True when the value is an https URL with a public DNS host name (no IP literal, no special-use
   * name), no credentials, no fragment and the default port (SPEC section 4.7.1). These URLs are
   * reported, never fetched.
   *
   * @param value a URL from a record
   * @return whether the record may carry it
   */
  public static boolean isSafeHttpsUrl(String value) {
    UrlParts url = UrlParts.parse(value);
    if (url == null || !url.scheme.equals("https")) return false;
    if (!url.username.isEmpty() || !url.password.isEmpty() || !url.fragment.isEmpty()) return false;
    if (!url.port.isEmpty() && !url.port.equals("443")) return false;
    if (url.host.startsWith("[")) return false;
    String host = asciiHost(url.host);
    if (host == null) return false;
    return isSafeHost(host) && !isSpecialUseName(host);
  }

  /**
   * The outcome of normalising a resolver's input.
   *
   * @param domain the domain to query, when the input is usable
   * @param error why the input is refused, otherwise
   * @param message a plain-English explanation of the refusal
   */
  public record NormalisedInput(String domain, ErrorCode error, String message) {
    /** True when {@link #domain()} is set. */
    public boolean ok() {
      return error == null;
    }

    static NormalisedInput domain(String domain) {
      return new NormalisedInput(domain, null, null);
    }

    static NormalisedInput refused(ErrorCode code, String message) {
      return new NormalisedInput(null, code, message);
    }
  }

  /**
   * Exactly one of {@code domain} and {@code website}, normalised to the domain to query: lower
   * case, IDN to A-labels, one trailing dot dropped. {@code www.} is never stripped. An empty
   * string counts as absent.
   *
   * @param domain a host name, or null
   * @param website a website address, or null
   * @return the domain, or why the input is refused
   */
  public static NormalisedInput normaliseInput(String domain, String website) {
    boolean hasDomain = domain != null && !domain.isEmpty();
    boolean hasWebsite = website != null && !website.isEmpty();
    if (hasDomain && hasWebsite) return NormalisedInput.refused(ErrorCode.BOTH_INPUTS, "Give either domain or website, not both.");
    if (hasDomain) return normaliseDomain(domain);
    if (hasWebsite) return domainFromWebsite(website);
    return NormalisedInput.refused(ErrorCode.MISSING_INPUT, "Give a domain (such as example.com) or a website address.");
  }

  /**
   * A queried domain, normalised. A host only: a URL, a port, credentials or an IP literal is refused.
   *
   * @param raw the domain as given
   * @return the domain, or why it is refused
   */
  public static NormalisedInput normaliseDomain(String raw) {
    String trimmed = Text.jsTrim(raw);
    if (trimmed.isEmpty()) return NormalisedInput.refused(ErrorCode.INVALID_DOMAIN, "The domain is empty.");
    if (trimmed.length() > 254) {
      return NormalisedInput.refused(ErrorCode.INVALID_DOMAIN, "The domain is longer than 253 characters.");
    }
    if (DOMAIN_FORBIDDEN.matcher(trimmed).find()) {
      return NormalisedInput.refused(ErrorCode.INVALID_DOMAIN,
          "Give a host name such as example.com, not a URL. To pass a website address, use the website input.");
    }
    return hostToDomain(trimmed);
  }

  /**
   * The host of a website address (http or https), normalised as {@link #normaliseDomain(String)}.
   * The path is ignored; a missing scheme is taken as https.
   *
   * @param raw the website address as given
   * @return the domain, or why it is refused
   */
  public static NormalisedInput domainFromWebsite(String raw) {
    String trimmed = Text.jsTrim(raw);
    if (trimmed.isEmpty()) return NormalisedInput.refused(ErrorCode.INVALID_WEBSITE, "The website is empty.");
    if (trimmed.length() > 2048) {
      return NormalisedInput.refused(ErrorCode.INVALID_WEBSITE, "The website address is longer than 2048 characters.");
    }
    String withScheme = SCHEME.matcher(trimmed).find() ? trimmed : "https://" + trimmed;
    UrlParts url = UrlParts.parse(withScheme);
    if (url == null) return NormalisedInput.refused(ErrorCode.INVALID_WEBSITE, "The website is not a valid URL.");
    if (!url.scheme.equals("https") && !url.scheme.equals("http")) {
      return NormalisedInput.refused(ErrorCode.INVALID_WEBSITE, "Only http and https website addresses are accepted.");
    }
    if (!url.username.isEmpty() || !url.password.isEmpty()) {
      return NormalisedInput.refused(ErrorCode.INVALID_WEBSITE, "A website address with a user name or password is refused.");
    }
    if (url.host.startsWith("[")) {
      return NormalisedInput.refused(ErrorCode.INVALID_WEBSITE, "An IP address is not a business domain.");
    }
    String decoded = percentDecode(url.host);
    if (decoded == null) return NormalisedInput.refused(ErrorCode.INVALID_WEBSITE, "The website is not a valid URL.");
    NormalisedInput out = hostToDomain(decoded);
    if (!out.ok() && out.error() == ErrorCode.INVALID_DOMAIN) {
      return NormalisedInput.refused(ErrorCode.INVALID_WEBSITE, out.message());
    }
    return out;
  }

  private static NormalisedInput hostToDomain(String raw) {
    String host = asciiHost(stripOneDot(raw));
    if (host == null) return NormalisedInput.refused(ErrorCode.INVALID_DOMAIN, "The domain is not a valid host name.");
    host = stripOneDot(host);
    if (host.startsWith("[") || IPV4ISH.matcher(host).matches()) {
      return NormalisedInput.refused(ErrorCode.INVALID_DOMAIN, "An IP address is not a business domain.");
    }
    if (!isSafeHost(host)) return NormalisedInput.refused(ErrorCode.INVALID_DOMAIN, "The domain is not a valid public host name.");
    if (isNonPublicHost(host)) {
      return NormalisedInput.refused(ErrorCode.NON_PUBLIC_DOMAIN,
          "The domain ends in a special-use or private-network name, so it has no public ABIZ record.");
    }
    return NormalisedInput.domain(host);
  }

  /**
   * A URL host as the WHATWG URL parser leaves it: lower case and IDN to A-labels. Null when the
   * parser would refuse it, including a host that "ends in a number" but is not a dotted IPv4
   * address. A valid IPv4 address in any notation becomes dotted decimal.
   */
  static String asciiHost(String host) {
    if (host.isEmpty()) return null;
    String ascii = toAscii(host.toLowerCase(Locale.ROOT));
    if (ascii == null) return null;
    ascii = ascii.toLowerCase(Locale.ROOT);
    if (ascii.isEmpty()) return null;
    for (int i = 0; i < ascii.length(); i++) {
      char c = ascii.charAt(i);
      if (c <= 0x20 || c == 0x7f || "#%/:<>?@[\\]^|".indexOf(c) >= 0) return null;
    }
    String[] labels = ascii.split("\\.", -1);
    int last = labels.length - 1;
    if (last > 0 && labels[last].isEmpty()) last--;
    String tail = labels[last];
    if (ALL_DIGITS.matcher(tail).matches() || HEX_NUMBER.matcher(tail).matches()) {
      String v4 = whatwgIpv4(ascii);
      return v4; // a dotted IPv4 address, or null when the parser fails
    }
    return ascii;
  }

  /**
   * IDN to A-labels. {@link IDN} implements IDNA2003, which maps the UTS #46 deviation characters
   * {@code ß} and {@code ς} to {@code ss} and {@code σ}; the WHATWG URL parser (UTS #46,
   * non-transitional) keeps them, so {@code straße.de} is {@code xn--strae-oqa.de}, a different
   * domain from {@code strasse.de}. Labels holding either are mapped character by character with
   * IDNA2003 and then Punycode-encoded here with the deviation characters kept.
   */
  private static String toAscii(String host) {
    if (host.indexOf('\u00df') < 0 && host.indexOf('\u03c2') < 0) {
      try {
        return IDN.toASCII(host);
      } catch (IllegalArgumentException e) {
        return null;
      }
    }
    String[] labels = host.split("[.\u3002\uff0e\uff61]", -1);
    StringBuilder out = new StringBuilder();
    for (int i = 0; i < labels.length; i++) {
      if (i > 0) out.append('.');
      String label = labels[i];
      if (label.indexOf('\u00df') < 0 && label.indexOf('\u03c2') < 0) {
        if (label.isEmpty()) continue;
        try {
          out.append(IDN.toASCII(label));
        } catch (IllegalArgumentException e) {
          return null;
        }
        continue;
      }
      StringBuilder mapped = new StringBuilder();
      for (int j = 0; j < label.length(); ) {
        int cp = label.codePointAt(j);
        j += Character.charCount(cp);
        if (cp == 0xdf || cp == 0x3c2) {
          mapped.appendCodePoint(cp);
          continue;
        }
        try {
          mapped.append(IDN.toUnicode(IDN.toASCII(new String(Character.toChars(cp)))));
        } catch (IllegalArgumentException e) {
          return null;
        }
      }
      String unicode = java.text.Normalizer.normalize(mapped, java.text.Normalizer.Form.NFC);
      String encoded = punycode(unicode);
      if (encoded == null || encoded.length() + 4 > 63) return null;
      out.append("xn--").append(encoded);
    }
    return out.toString();
  }

  /** RFC 3492 Punycode encoding of one label; null on overflow. */
  private static String punycode(String input) {
    final int base = 36;
    final int tMin = 1;
    final int tMax = 26;
    int[] cps = input.codePoints().toArray();
    StringBuilder out = new StringBuilder();
    for (int cp : cps) if (cp < 0x80) out.append((char) cp);
    int basic = out.length();
    int handled = basic;
    if (basic > 0) out.append('-');
    int n = 0x80;
    long delta = 0;
    int bias = 72;
    while (handled < cps.length) {
      int m = Integer.MAX_VALUE;
      for (int cp : cps) if (cp >= n && cp < m) m = cp;
      delta += (long) (m - n) * (handled + 1);
      if (delta > Integer.MAX_VALUE) return null;
      n = m;
      for (int cp : cps) {
        if (cp < n) delta++;
        if (cp == n) {
          long q = delta;
          for (int k = base; ; k += base) {
            int t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
            if (q < t) break;
            out.append(punyDigit((int) (t + (q - t) % (base - t))));
            q = (q - t) / (base - t);
          }
          out.append(punyDigit((int) q));
          // Bias adaptation (RFC 3492 section 6.1).
          long d = handled == basic ? delta / 700 : delta / 2;
          d += d / (handled + 1);
          int k = 0;
          while (d > ((base - tMin) * tMax) / 2) {
            d /= base - tMin;
            k += base;
          }
          bias = (int) (k + ((base - tMin + 1) * d) / (d + 38));
          delta = 0;
          handled++;
        }
      }
      delta++;
      n++;
    }
    return out.toString();
  }

  private static char punyDigit(int d) {
    return (char) (d < 26 ? 'a' + d : '0' + (d - 26));
  }

  /** The WHATWG IPv4 parser: up to four parts, decimal, octal or hex; null on failure. */
  private static String whatwgIpv4(String input) {
    String[] parts = input.split("\\.", -1);
    int count = parts.length;
    if (parts[count - 1].isEmpty() && count > 1) count--;
    if (count > 4) return null;
    long[] numbers = new long[count];
    for (int i = 0; i < count; i++) {
      String part = parts[i];
      if (part.isEmpty()) return null;
      int radix = 10;
      if (part.length() >= 2 && (part.startsWith("0x") || part.startsWith("0X"))) {
        radix = 16;
        part = part.substring(2);
      } else if (part.length() >= 2 && part.startsWith("0")) {
        radix = 8;
        part = part.substring(1);
      }
      if (part.isEmpty()) {
        numbers[i] = 0;
        continue;
      }
      try {
        java.math.BigInteger n = new java.math.BigInteger(part, radix);
        if (n.bitLength() > 40) return null;
        numbers[i] = n.longValue();
      } catch (NumberFormatException e) {
        return null;
      }
    }
    for (int i = 0; i < count - 1; i++) if (numbers[i] > 255) return null;
    if (numbers[count - 1] >= Math.pow(256, 5 - count)) return null;
    long ipv4 = numbers[count - 1];
    for (int i = 0; i < count - 1; i++) ipv4 += numbers[i] * (long) Math.pow(256, 3 - i);
    return ((ipv4 >> 24) & 0xff) + "." + ((ipv4 >> 16) & 0xff) + "." + ((ipv4 >> 8) & 0xff) + "." + (ipv4 & 0xff);
  }

  private static String stripOneDot(String s) {
    return s.endsWith(".") ? s.substring(0, s.length() - 1) : s;
  }

  private static String percentDecode(String s) {
    if (s.indexOf('%') < 0) return s;
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c == '%' && i + 2 < s.length() && isHex(s.charAt(i + 1)) && isHex(s.charAt(i + 2))) {
        out.write(Integer.parseInt(s.substring(i + 1, i + 3), 16));
        i += 2;
      } else {
        byte[] bytes = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
        out.write(bytes, 0, bytes.length);
      }
    }
    try {
      return StandardCharsets.UTF_8.newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(out.toByteArray()))
          .toString();
    } catch (CharacterCodingException e) {
      return null;
    }
  }

  private static boolean isHex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
  }

  /**
   * The parts of an http(s) URL as the WHATWG URL parser splits them, for the few things the
   * reference reads from {@code new URL()}: scheme, user name, password, host, port and fragment.
   * Null when the parser would refuse the text.
   */
  static final class UrlParts {
    final String scheme;
    final String username;
    final String password;
    final String host;
    final String port;
    final String fragment;

    private UrlParts(String scheme, String username, String password, String host, String port, String fragment) {
      this.scheme = scheme;
      this.username = username;
      this.password = password;
      this.host = host;
      this.port = port;
      this.fragment = fragment;
    }

    static UrlParts parse(String input) {
      // Leading and trailing C0 controls and spaces are stripped; tabs and newlines removed anywhere.
      int start = 0;
      int end = input.length();
      while (start < end && input.charAt(start) <= 0x20) start++;
      while (end > start && input.charAt(end - 1) <= 0x20) end--;
      String s = input.substring(start, end).replace("\t", "").replace("\n", "").replace("\r", "");
      java.util.regex.Matcher m = SCHEME.matcher(s);
      if (!m.find()) return null;
      String scheme = s.substring(0, m.end() - 1).toLowerCase(Locale.ROOT);
      String rest = s.substring(m.end());
      if (!scheme.equals("http") && !scheme.equals("https")) {
        // Not a special scheme: the reference only needs to know it is neither http nor https.
        return new UrlParts(scheme, "", "", "", "", "");
      }
      int i = 0;
      while (i < rest.length() && (rest.charAt(i) == '/' || rest.charAt(i) == '\\')) i++;
      rest = rest.substring(i);
      int authEnd = rest.length();
      for (int j = 0; j < rest.length(); j++) {
        char c = rest.charAt(j);
        if (c == '/' || c == '\\' || c == '?' || c == '#') {
          authEnd = j;
          break;
        }
      }
      String authority = rest.substring(0, authEnd);
      String after = rest.substring(authEnd);
      int hash = after.indexOf('#');
      String fragment = hash < 0 ? "" : after.substring(hash + 1);
      String username = "";
      String password = "";
      int at = authority.lastIndexOf('@');
      if (at >= 0) {
        String userinfo = authority.substring(0, at);
        int colon = userinfo.indexOf(':');
        username = colon < 0 ? userinfo : userinfo.substring(0, colon);
        password = colon < 0 ? "" : userinfo.substring(colon + 1);
        authority = authority.substring(at + 1);
      }
      String host;
      String port = "";
      if (authority.startsWith("[")) {
        int close = authority.indexOf(']');
        if (close < 0) return null;
        host = authority.substring(0, close + 1);
        String tail = authority.substring(close + 1);
        if (!tail.isEmpty()) {
          if (!tail.startsWith(":")) return null;
          port = tail.substring(1);
        }
      } else {
        int colon = authority.lastIndexOf(':');
        host = colon < 0 ? authority : authority.substring(0, colon);
        port = colon < 0 ? "" : authority.substring(colon + 1);
      }
      if (host.isEmpty()) return null;
      if (!port.isEmpty()) {
        if (!ALL_DIGITS.matcher(port).matches()) return null;
        java.math.BigInteger n = new java.math.BigInteger(port);
        if (n.compareTo(java.math.BigInteger.valueOf(65535)) > 0) return null;
        int value = n.intValue();
        int defaultPort = scheme.equals("https") ? 443 : 80;
        port = value == defaultPort ? "" : Integer.toString(value);
      }
      if (!host.startsWith("[")) {
        String decoded = percentDecode(host);
        if (decoded == null) return null;
        String ascii = asciiHost(decoded);
        if (ascii == null) return null;
        host = ascii;
      }
      return new UrlParts(scheme, username, password, host, port, fragment);
    }
  }
}
