package org.abizrecord.abiz;

/**
 * The outcome of {@link Assertions#parse(String)}: an assertion, or an error code and a message.
 *
 * @param assertion the assertion, when the value parses
 * @param code why it does not, otherwise: {@code bad_pointer}, {@code duplicate_tag},
 *     {@code missing_h}, {@code unsafe_host} or {@code invalid_key}
 * @param message a plain-English explanation of the failure
 */
public record AssertionResult(Assertion assertion, ErrorCode code, String message) {
  /** True when {@link #assertion()} is set. */
  public boolean ok() {
    return assertion != null;
  }

  static AssertionResult of(Assertion assertion) {
    return new AssertionResult(assertion, null, null);
  }

  static AssertionResult fail(ErrorCode code, String message) {
    return new AssertionResult(null, code, message);
  }
}
