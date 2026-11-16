package org.abizrecord.abiz;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Which resolved addresses a fetch may connect to (SPEC section 9): public unicast IPv4 outside
 * every special-purpose block in the IANA registry, or global unicast IPv6 (2000::/3) outside the
 * documentation, 6to4, Teredo and other IETF ranges. Everything else, IPv4-mapped IPv6 included,
 * is refused. A port of {@code address.ts} in the reference resolver.
 */
public final class Addresses {
  private Addresses() {}

  private static final Pattern V4 = Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\z");
  private static final Pattern V4_TAIL = Pattern.compile("^(.*:)(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\z");
  private static final Pattern GROUP = Pattern.compile("^[0-9a-f]{1,4}\\z");

  /** [network, prefix length] of IPv4 special-purpose blocks that are never a public web origin. */
  private static final long[][] V4_SPECIAL = {
      {ip4(0, 0, 0, 0), 8}, {ip4(10, 0, 0, 0), 8}, {ip4(100, 64, 0, 0), 10}, {ip4(127, 0, 0, 0), 8},
      {ip4(169, 254, 0, 0), 16}, {ip4(172, 16, 0, 0), 12}, {ip4(192, 0, 0, 0), 24}, {ip4(192, 0, 2, 0), 24},
      {ip4(192, 31, 196, 0), 24}, {ip4(192, 52, 193, 0), 24}, {ip4(192, 88, 99, 0), 24}, {ip4(192, 168, 0, 0), 16},
      {ip4(192, 175, 48, 0), 24}, {ip4(198, 18, 0, 0), 15}, {ip4(198, 51, 100, 0), 24}, {ip4(203, 0, 113, 0), 24},
      {ip4(224, 0, 0, 0), 4}, {ip4(240, 0, 0, 0), 4},
  };

  /**
   * True only for an address a fetch may connect to.
   *
   * @param address an IPv4 address in dotted decimal or an IPv6 address in text form
   * @return whether it is public unicast; false for anything that is not an address
   */
  public static boolean isPublic(String address) {
    Long v4 = parseV4(address);
    if (v4 != null) return v4Public(v4);
    int[] groups = ipv6Groups(address);
    return groups != null && v6Public(groups);
  }

  /**
   * True only for an address a fetch may connect to.
   *
   * @param raw 4 bytes (IPv4) or 16 bytes (IPv6), as in an A or AAAA record
   * @return whether it is public unicast
   */
  public static boolean isPublic(byte[] raw) {
    if (raw == null) return false;
    if (raw.length == 4) return v4Public(ip4(raw[0] & 0xff, raw[1] & 0xff, raw[2] & 0xff, raw[3] & 0xff));
    if (raw.length != 16) return false;
    int[] groups = new int[8];
    for (int i = 0; i < 8; i++) groups[i] = ((raw[2 * i] & 0xff) << 8) | (raw[2 * i + 1] & 0xff);
    return v6Public(groups);
  }

  private static boolean v4Public(long n) {
    for (long[] block : V4_SPECIAL) {
      long mask = block[1] == 0 ? 0 : (0xffffffffL << (32 - block[1])) & 0xffffffffL;
      if ((n & mask) == block[0]) return false;
    }
    return true;
  }

  private static boolean v6Public(int[] g) {
    int first = g[0];
    if ((first & 0xe000) != 0x2000) return false; // outside 2000::/3: ::ffff:0:0/96, 64:ff9b::/96, fc00::/7, fe80::/10 ...
    if (first == 0x2001 && g[1] == 0x0db8) return false; // 2001:db8::/32 documentation
    if (first == 0x2001 && g[1] < 0x0200) return false; // 2001::/23 IETF protocol assignments (Teredo, ORCHID, benchmarking)
    if (first == 0x2002) return false; // 6to4: the embedded IPv4 is not checked
    if (first == 0x3fff && g[1] < 0x1000) return false; // 3fff::/20 documentation
    return true;
  }

  private static long ip4(int a, int b, int c, int d) {
    return ((long) a << 24) | ((long) b << 16) | ((long) c << 8) | d;
  }

  private static Long parseV4(String text) {
    Matcher m = V4.matcher(text);
    if (!m.matches()) return null;
    int[] o = new int[4];
    for (int i = 0; i < 4; i++) {
      o[i] = Integer.parseInt(m.group(i + 1));
      if (o[i] > 255) return null;
    }
    return ip4(o[0], o[1], o[2], o[3]);
  }

  /** The eight 16-bit groups of an IPv6 address (a dotted IPv4 tail allowed), or null. */
  static int[] ipv6Groups(String text) {
    String t = text.toLowerCase(Locale.ROOT);
    if (t.startsWith("[")) t = t.substring(1);
    if (t.endsWith("]")) t = t.substring(0, t.length() - 1);
    int zone = t.indexOf('%');
    if (zone >= 0) t = t.substring(0, zone);
    Matcher tail = V4_TAIL.matcher(t);
    if (tail.matches()) {
      Long n = parseV4(tail.group(2));
      if (n == null) return null;
      t = tail.group(1) + Long.toHexString(n >>> 16) + ":" + Long.toHexString(n & 0xffff);
    }
    String[] halves = t.split("::", -1);
    if (halves.length > 2) return null;
    String[] head = halves[0].isEmpty() ? new String[0] : halves[0].split(":", -1);
    String[] rest = halves.length == 2 && !halves[1].isEmpty() ? halves[1].split(":", -1) : new String[0];
    int fill = 8 - head.length - rest.length;
    if (halves.length == 2 ? fill < 1 : fill != 0) return null;
    int[] out = new int[8];
    int at = 0;
    for (String g : head) {
      if (!GROUP.matcher(g).matches()) return null;
      out[at++] = Integer.parseInt(g, 16);
    }
    if (halves.length == 2) at += fill;
    for (String g : rest) {
      if (!GROUP.matcher(g).matches()) return null;
      out[at++] = Integer.parseInt(g, 16);
    }
    return out;
  }
}
