package org.abizrecord.abiz;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;

/**
 * The outcome of a resolution, with the same status and error code as the hosted resolver.
 *
 * @param status the outcome
 * @param code null when resolved, else the error code
 * @param message null when resolved, else a plain-English explanation
 * @param retryable true when a later attempt may succeed
 * @param details where and why (at most 25), for publisher errors
 * @param record the record exactly as published, only when resolved
 * @param domain the domain queried (normalised), or the domain as given when it was refused; null
 *     when only a website was given and refused, or nothing was given
 * @param discovery how the assertion was found; null when the input was refused
 * @param warnings things worth knowing that did not change the result
 */
public record ResolveResult(Status status, ErrorCode code, String message, boolean retryable, List<Problem> details,
    JsonNode record, String domain, Discovery discovery, List<Warning> warnings) {
  /** Creates a result. */
  public ResolveResult {
    details = details == null ? List.of() : List.copyOf(details);
    warnings = warnings == null ? List.of() : List.copyOf(warnings);
  }

  /** True when the record was found and every check passed. */
  public boolean resolved() {
    return status == Status.RESOLVED;
  }
}
