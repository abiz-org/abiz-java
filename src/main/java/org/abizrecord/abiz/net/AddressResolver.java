package org.abizrecord.abiz.net;

import java.util.List;

/**
 * Looks up a host's A and AAAA records for the fetch guard. The addresses are returned as raw
 * bytes (4 or 16) so that an IPv4-mapped IPv6 answer stays IPv6 and is refused.
 */
@FunctionalInterface
public interface AddressResolver {
  /**
   * Look up the host's addresses.
   *
   * @param host a DNS host name
   * @return the addresses, or a failure; implementations should not throw
   */
  Result resolve(String host);

  /** The outcome of an address lookup. */
  sealed interface Result permits Found, Failed {}

  /**
   * The lookup completed. An empty list means the name has no A or AAAA record.
   *
   * @param addresses raw 4- or 16-byte addresses
   */
  record Found(List<byte[]> addresses) implements Result {
    /** Creates the outcome. */
    public Found {
      addresses = List.copyOf(addresses);
    }
  }

  /** The lookup failed (timeout, SERVFAIL, network). */
  record Failed() implements Result {}
}
