package org.abizrecord.abiz;

import java.util.Locale;

/**
 * Stable error codes, the same as the hosted resolver's ({@code resolve.abizrecord.org}). Each code
 * belongs to one {@link Status}; some are retryable (a later attempt may succeed).
 */
public enum ErrorCode {
  /** Neither a domain nor a website was given. */
  MISSING_INPUT(Status.INVALID_INPUT, false, "Give a domain (such as example.com) or a website address."),
  /** Both a domain and a website were given. */
  BOTH_INPUTS(Status.INVALID_INPUT, false, "Give either domain or website, not both."),
  /** The domain is not a host name (a URL, port, credentials or IP literal, for example). */
  INVALID_DOMAIN(Status.INVALID_INPUT, false, "The domain is not a valid public host name."),
  /** The website address is not a usable http or https URL. */
  INVALID_WEBSITE(Status.INVALID_INPUT, false, "The website address is not valid."),
  /** The domain is a special-use or private-network name. */
  NON_PUBLIC_DOMAIN(Status.INVALID_INPUT, false, "The domain is a special-use or private-network name."),
  /** DNS answered with no {@code v=abiz1} value and the well-known file gave no assertion. */
  MISSING_TXT(Status.NOT_FOUND, false,
      "The DNS query succeeded and there is no v=abiz1 TXT record at this name, and /.well-known/abiz.json is missing or invalid, so the domain publishes no ABIZ record."),
  /** More than one {@code v=abiz1} TXT value is published. */
  MULTIPLE_TXT(Status.CONFLICT, false,
      "More than one v=abiz1 TXT record is published at this name. The publisher must keep exactly one."),
  /** The assertion is malformed. */
  BAD_POINTER(Status.INVALID_RECORD, false, "The ABIZ TXT record is malformed."),
  /** The assertion repeats a recognised tag. */
  DUPLICATE_TAG(Status.INVALID_RECORD, false, "The ABIZ TXT record repeats a tag."),
  /** The assertion has no {@code h=} tag. */
  MISSING_H(Status.INVALID_RECORD, false, "The ABIZ TXT record has no h= tag."),
  /** The record host is a special-use name, or the fetch guard refused its addresses. */
  UNSAFE_HOST(Status.INVALID_RECORD, false, "The record host is not a public address this library will fetch."),
  /** {@code p=} is missing or is not an Ed25519 public key in standard base64. */
  INVALID_KEY(Status.INVALID_RECORD, false,
      "The ABIZ TXT record has no p= key, or a p= value that is not an Ed25519 public key in standard base64."),
  /** The record host did not serve the record (no public address, a redirect, or a non-200 answer). */
  FETCH_FAILED(Status.INVALID_RECORD, false, "The record host did not serve the record."),
  /** The record is over 64 KiB, nests deeper than 16 or has more than 5,000 members. */
  RECORD_TOO_LARGE(Status.INVALID_RECORD, false,
      "The record is larger or more deeply nested than this library accepts (64 KiB, depth 16, 5,000 members)."),
  /** The record is not JSON, is served with a non-JSON content type, or repeats a member name. */
  NOT_JSON(Status.INVALID_RECORD, false, "The record host did not answer with an I-JSON document."),
  /** The record fails the JSON Schema or a semantic check. */
  SCHEMA_INVALID(Status.INVALID_RECORD, false, "The document does not conform to the ABIZ business record schema."),
  /** {@code identity_host} differs from {@code h}. */
  IDENTITY_HOST_MISMATCH(Status.INVALID_RECORD, false, "The record's identity_host does not match the DNS h= value."),
  /** {@code domains} does not include the queried domain. */
  DOMAIN_NOT_CLAIMED(Status.INVALID_RECORD, false, "The record's domains list does not include the queried domain."),
  /** The business key in DNS and the record's registration fields disagree. */
  BUSINESS_KEY_MISMATCH(Status.INVALID_RECORD, false,
      "The business key in DNS and the record's registration fields disagree."),
  /** {@code public_key} is not the key published as {@code p=}. */
  PUBLIC_KEY_MISMATCH(Status.INVALID_RECORD, false,
      "The record's public_key is not the Ed25519 key published as p= in DNS."),
  /** {@code signature} is missing or does not verify. */
  SIGNATURE_INVALID(Status.INVALID_RECORD, false,
      "The record's signature is missing or does not verify with its public_key (Ed25519 over the RFC 8785 form of the record without signature)."),
  /** The TXT lookup timed out or the network failed. */
  DNS_TIMEOUT(Status.UNAVAILABLE, true,
      "The ABIZ TXT lookup could not be completed. This does not establish that no ABIZ record exists."),
  /** The DNS resolver answered SERVFAIL, REFUSED or something unreadable. */
  DNS_FAILURE(Status.UNAVAILABLE, true,
      "The DNS resolver could not answer for this name (for example SERVFAIL). This does not establish that no ABIZ record exists."),
  /** The record host or well-known host did not answer in time. */
  UPSTREAM_TIMEOUT(Status.UNAVAILABLE, true,
      "The host did not answer in time. This does not establish that the record is missing."),
  /** The record host or well-known host is temporarily unavailable. */
  ORIGIN_UNAVAILABLE(Status.UNAVAILABLE, true,
      "The host is temporarily unavailable. This does not establish that the record is missing.");

  private final Status status;
  private final boolean retryable;
  private final String defaultMessage;

  ErrorCode(Status status, boolean retryable, String defaultMessage) {
    this.status = status;
    this.retryable = retryable;
    this.defaultMessage = defaultMessage;
  }

  /** The wire code, for example {@code signature_invalid}. */
  public String code() {
    return name().toLowerCase(Locale.ROOT);
  }

  /** The status this code is reported under. */
  public Status status() {
    return status;
  }

  /** True when a later attempt may succeed (DNS or the host was unavailable). */
  public boolean retryable() {
    return retryable;
  }

  /** A plain-English explanation of the code. */
  public String defaultMessage() {
    return defaultMessage;
  }

  /**
   * The code with this wire name.
   *
   * @param code a wire code such as {@code bad_pointer}
   * @return the code
   * @throws IllegalArgumentException when there is no such code
   */
  public static ErrorCode fromCode(String code) {
    return valueOf(code.toUpperCase(Locale.ROOT));
  }

  @Override
  public String toString() {
    return code();
  }
}
