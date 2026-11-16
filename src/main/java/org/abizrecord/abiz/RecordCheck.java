package org.abizrecord.abiz;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;

/**
 * The outcome of checking a record offline against a queried domain and an assertion.
 *
 * @param code null when the record is accepted, else the first failing check
 * @param details where and why (at most 25), empty when accepted
 * @param record the parsed record, when it parsed as JSON
 */
public record RecordCheck(ErrorCode code, List<Problem> details, JsonNode record) {
  /** Creates a result. */
  public RecordCheck {
    details = details == null ? List.of() : List.copyOf(details.size() > RecordValidator.MAX_PROBLEMS
        ? details.subList(0, RecordValidator.MAX_PROBLEMS) : details);
  }

  /** True when every check passed. */
  public boolean ok() {
    return code == null;
  }
}
