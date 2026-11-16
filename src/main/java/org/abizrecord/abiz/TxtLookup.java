package org.abizrecord.abiz;

import java.util.List;
import java.util.Objects;

/**
 * The DNS port: one TXT query. Absence and failure are different outcomes and must stay different:
 * a timeout or SERVFAIL is never reported as NXDOMAIN or NODATA. Supply your own implementation to
 * use DNS-over-HTTPS, a cache or a fixed answer in tests; {@link org.abizrecord.abiz.net.DnsjavaTxtLookup}
 * is the default.
 */
@FunctionalInterface
public interface TxtLookup {
  /**
   * Query TXT records at {@code name}.
   *
   * @param name the owner name, for example {@code _abiz.example.com}
   * @return the outcome; implementations should not throw
   */
  Result lookup(String name);

  /** The outcome of a TXT query. */
  sealed interface Result permits Answer, NxDomain, NoData, Failure {}

  /**
   * TXT records were returned.
   *
   * @param values one string per TXT record, its character-strings joined with nothing between them
   */
  record Answer(List<String> values) implements Result {
    /** Creates an answer. */
    public Answer {
      values = List.copyOf(values);
    }
  }

  /** The name does not exist (NXDOMAIN). */
  record NxDomain() implements Result {}

  /** The name exists and has no TXT records (NOERROR with an empty answer). */
  record NoData() implements Result {}

  /**
   * The query failed. This never means the record is absent.
   *
   * @param reason what went wrong
   */
  record Failure(Reason reason) implements Result {
    /** Creates a failure. */
    public Failure {
      Objects.requireNonNull(reason, "reason");
    }
  }

  /** Why a TXT query failed. {@code TIMEOUT} and {@code NETWORK} give {@code dns_timeout}; the rest {@code dns_failure}. */
  enum Reason {
    /** No answer in time. */
    TIMEOUT,
    /** The resolver answered SERVFAIL. */
    SERVFAIL,
    /** The resolver answered REFUSED. */
    REFUSED,
    /** The answer could not be read, or had another error code. */
    MALFORMED,
    /** The resolver could not be reached. */
    NETWORK
  }
}
