package org.abizrecord.abiz;

import java.util.Map;
import java.util.Objects;

/**
 * A parsed {@code _abiz} assertion (SPEC section 3), from DNS or the well-known file.
 *
 * @param h the canonical record host: host lower case, trailing dot dropped, path as published
 * @param k the business key exactly as published, or null when absent
 * @param p the Ed25519 public key, 44 characters of standard base64
 * @param unknown tags the specification does not define, first value of each, kept for reference
 */
public record Assertion(String h, String k, String p, Map<String, String> unknown) {
  /** Creates an assertion. */
  public Assertion {
    Objects.requireNonNull(h, "h");
    Objects.requireNonNull(p, "p");
    unknown = unknown == null ? Map.of() : Map.copyOf(unknown);
  }
}
