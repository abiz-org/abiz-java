package org.abizrecord.abiz;

import java.util.Objects;

/**
 * The HTTP port: one guarded GET. Implementations must apply the fetch guard (SPEC section 9):
 * resolve the host and refuse unless every address is public, connect to a checked address, HTTPS
 * on port 443 with the certificate verified, no redirects followed, 5 seconds, 64 KiB, and
 * {@code Accept: application/json}. {@link org.abizrecord.abiz.net.GuardedHttpsFetcher} is the
 * default.
 */
@FunctionalInterface
public interface RecordFetcher {
  /**
   * GET the URL.
   *
   * @param url an {@code https://} URL built by the resolver
   * @return the outcome; implementations should not throw
   */
  Outcome fetch(String url);

  /** The outcome of a fetch. */
  sealed interface Outcome permits Response, Blocked, NoAddress, DnsError, Timeout, Network {}

  /**
   * The host answered.
   *
   * @param status the HTTP status
   * @param contentType the {@code Content-Type} header, or null
   * @param body the body decoded as UTF-8 (empty for a non-200 answer), or null when it was larger
   *     than 64 KiB
   */
  record Response(int status, String contentType, String body) implements Outcome {}

  /**
   * The guard refused the URL or the host's addresses.
   *
   * @param message why
   */
  record Blocked(String message) implements Outcome {
    /** Creates the outcome. */
    public Blocked {
      Objects.requireNonNull(message, "message");
    }
  }

  /** The host name exists and has no A or AAAA record. */
  record NoAddress() implements Outcome {}

  /** The host's addresses could not be looked up. */
  record DnsError() implements Outcome {}

  /** The host did not answer within the time limit. */
  record Timeout() implements Outcome {}

  /** The connection or TLS failed. */
  record Network() implements Outcome {}
}
