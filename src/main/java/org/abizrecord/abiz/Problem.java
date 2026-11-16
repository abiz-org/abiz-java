package org.abizrecord.abiz;

import java.util.Objects;

/**
 * One problem found in a record or an assertion: where, and what.
 *
 * @param path a JSON Pointer into the record, {@code $} for the whole record, or the DNS name or URL
 *     the problem is about
 * @param message a plain-English explanation
 */
public record Problem(String path, String message) {
  /** Creates a problem. */
  public Problem {
    Objects.requireNonNull(path, "path");
    Objects.requireNonNull(message, "message");
  }
}
