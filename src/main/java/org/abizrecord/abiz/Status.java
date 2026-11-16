package org.abizrecord.abiz;

/** The outcome of a resolution, as the hosted resolver names it. */
public enum Status {
  /** The record was found and every check passed. */
  RESOLVED("resolved"),
  /** The domain or website given could not be used. No DNS query was sent. */
  INVALID_INPUT("invalid_input"),
  /** DNS answered and there is no ABIZ assertion, and the well-known file gave none. */
  NOT_FOUND("not_found"),
  /** More than one {@code v=abiz1} TXT record is published. */
  CONFLICT("conflict"),
  /** An assertion or record was found and failed a check. */
  INVALID_RECORD("invalid_record"),
  /** DNS or the record host could not be reached. This does not mean there is no record. */
  UNAVAILABLE("unavailable");

  private final String wireName;

  Status(String wireName) {
    this.wireName = wireName;
  }

  /** The name used by the hosted resolver and the test vectors, for example {@code invalid_record}. */
  public String wireName() {
    return wireName;
  }

  @Override
  public String toString() {
    return wireName;
  }
}
