package org.abizrecord.abiz;

/**
 * Something worth knowing about a result that did not change it.
 *
 * @param code {@code content_type} (the record was read as JSON without a JSON content type) or
 *     {@code try_apex} (nothing at a {@code www.} name; the apex is a different domain, not checked)
 * @param message a plain-English explanation
 * @param domain for {@code try_apex}, the domain that might be queried instead; otherwise null
 */
public record Warning(String code, String message, String domain) {}
