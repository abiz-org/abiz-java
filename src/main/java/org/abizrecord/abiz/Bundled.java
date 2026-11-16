package org.abizrecord.abiz;

import java.io.IOException;
import java.io.InputStream;

/** The files bundled in the jar, pinned by SHA-256 (checked by the test suite). */
final class Bundled {
  private Bundled() {}

  static final String RECORD_SCHEMA = "abiz-business-record-v1.1.schema.json";
  static final String WELL_KNOWN_SCHEMA = "abiz-well-known-v1.1.schema.json";
  static final String ISO3166 = "iso3166.json";

  static InputStream open(String name) throws IOException {
    InputStream in = Bundled.class.getResourceAsStream(name);
    if (in == null) throw new IOException("bundled resource missing: " + name);
    return in;
  }
}
