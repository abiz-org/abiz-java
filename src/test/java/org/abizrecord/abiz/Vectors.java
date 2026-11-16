package org.abizrecord.abiz;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/** Loads the shared test vectors from {@code test-vectors/} (set by Maven as {@code abiz.testVectors}). */
final class Vectors {
  private Vectors() {}

  private static final ObjectMapper MAPPER = new ObjectMapper();

  static Path dir() {
    String configured = System.getProperty("abiz.testVectors");
    Path dir = configured != null ? Paths.get(configured) : Paths.get("test-vectors");
    if (!Files.isDirectory(dir)) throw new IllegalStateException("test vectors not found at " + dir.toAbsolutePath());
    return dir;
  }

  static JsonNode load(String file) {
    try {
      JsonNode root = MAPPER.readTree(dir().resolve(file).toFile());
      if (root.get("format").asInt() != 1) throw new IllegalStateException(file + " is not test-vector format 1");
      return root;
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /** A text member, or null when absent or JSON null. */
  static String text(JsonNode node, String field) {
    JsonNode value = node.get(field);
    return value == null || value.isNull() ? null : value.asText();
  }
}
