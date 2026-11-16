package org.abizrecord.abiz;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** The bundled {@code iso3166.json} (LGPL-2.1, see NOTICE): assigned countries and selected subdivisions. */
final class Iso3166 {
  private Iso3166() {}

  static final Set<String> COUNTRIES;
  static final Map<String, Set<String>> SUBDIVISIONS;

  static {
    try (InputStream in = Bundled.open(Bundled.ISO3166)) {
      JsonNode root = StrictJson.mapper().readTree(in);
      Set<String> countries = new HashSet<>();
      for (JsonNode code : root.get("countries")) countries.add(code.asText());
      Map<String, Set<String>> subdivisions = new HashMap<>();
      for (Map.Entry<String, JsonNode> entry : root.get("subdivisions").properties()) {
        Set<String> codes = new HashSet<>();
        for (JsonNode code : entry.getValue()) codes.add(code.asText());
        subdivisions.put(entry.getKey(), Set.copyOf(codes));
      }
      COUNTRIES = Set.copyOf(countries);
      SUBDIVISIONS = Map.copyOf(subdivisions);
    } catch (IOException e) {
      throw new UncheckedIOException("cannot read the bundled iso3166.json", e);
    }
  }

  /** True when {@code code} is an assigned ISO 3166-1 alpha-2 code, in any case ({@code kp} included). */
  static boolean isAssignedCountry(String code) {
    return code.length() == 2
        && isAsciiLetter(code.charAt(0))
        && isAsciiLetter(code.charAt(1))
        && COUNTRIES.contains(code.toLowerCase(Locale.ROOT));
  }

  private static boolean isAsciiLetter(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
  }
}
