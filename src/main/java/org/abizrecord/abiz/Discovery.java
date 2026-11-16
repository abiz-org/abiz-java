package org.abizrecord.abiz;

import java.util.List;

/**
 * How the assertion was found and what was fetched.
 *
 * @param method {@code dns_txt} or {@code well_known}
 * @param owner the DNS name queried, {@code _abiz.<domain>}
 * @param dnsValue the {@code v=abiz1} value used, exactly as published; null when none was used or
 *     the assertion came from the well-known file
 * @param dnsValues for a conflict, every {@code v=abiz1} value found; otherwise empty
 * @param recordUrl the record address fetched, {@code https://<h>?format=json}, or null
 * @param wellKnown {@code not_checked}, {@code absent}, {@code invalid}, {@code unavailable} or {@code used}
 * @param wellKnownUrl the well-known file's address, when it was fetched
 */
public record Discovery(String method, String owner, String dnsValue, List<String> dnsValues, String recordUrl,
    String wellKnown, String wellKnownUrl) {
  /** Creates a discovery. */
  public Discovery {
    dnsValues = dnsValues == null ? List.of() : List.copyOf(dnsValues);
  }
}
