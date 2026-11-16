package org.abizrecord.abiz;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;

/**
 * I-JSON parsing (RFC 7493) with the resolver's limits: a repeated member name anywhere is an
 * error (Jackson's {@code STRICT_DUPLICATE_DETECTION} and {@code FAIL_ON_READING_DUP_TREE_KEY}),
 * trailing content is an error, and the text is measured for nesting depth and member count before
 * it is parsed.
 */
final class StrictJson {
  private StrictJson() {}

  /** Nesting deeper than this is {@code record_too_large}. */
  static final int MAX_DEPTH = 16;
  /** More object members than this, across every level, is {@code record_too_large}. */
  static final int MAX_KEYS = 5_000;

  private static final ObjectMapper MAPPER = JsonMapper.builder()
      .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
      .enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY)
      .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
      .disable(JsonReadFeature.ALLOW_NON_NUMERIC_NUMBERS)
      .disable(JsonReadFeature.ALLOW_LEADING_ZEROS_FOR_NUMBERS)
      .disable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)
      .build();

  static ObjectMapper mapper() {
    return MAPPER;
  }

  /** Why a text was refused. */
  enum Problem {
    INVALID_JSON,
    DUPLICATE_MEMBER,
    TOO_DEEP,
    TOO_MANY_KEYS
  }

  /** A parsed value, or the reason there is none. */
  record Result(JsonNode value, Problem problem) {
    boolean ok() {
      return problem == null;
    }
  }

  /** Measure, then parse. */
  static Result parse(String text) {
    Problem shape = shapeProblem(text);
    if (shape != null) return new Result(null, shape);
    return parseUnlimited(text);
  }

  /** Parse without the depth and member limits (still I-JSON). */
  static Result parseUnlimited(String text) {
    try (JsonParser parser = MAPPER.createParser(text)) {
      JsonNode node = MAPPER.readTree(parser);
      if (node == null || node.isMissingNode()) return new Result(null, Problem.INVALID_JSON);
      return new Result(node, null);
    } catch (JsonProcessingException e) {
      String message = String.valueOf(e.getOriginalMessage());
      boolean duplicate = message.startsWith("Duplicate field") || message.contains("Duplicate field");
      return new Result(null, duplicate ? Problem.DUPLICATE_MEMBER : Problem.INVALID_JSON);
    } catch (java.io.IOException e) {
      return new Result(null, Problem.INVALID_JSON);
    }
  }

  /**
   * One linear pass over the text, without parsing it: the deepest nesting and the number of
   * {@code :} outside strings (in valid JSON, one per object member). Invalid JSON gives a bounded,
   * meaningless count; it is parsed (and refused) afterwards. As {@code scanJson} in the reference.
   */
  static Problem shapeProblem(String text) {
    int depth = 0;
    int deepest = 0;
    int keys = 0;
    boolean inString = false;
    for (int i = 0; i < text.length(); i++) {
      char ch = text.charAt(i);
      if (inString) {
        if (ch == '\\') i++;
        else if (ch == '"') inString = false;
        continue;
      }
      if (ch == '"') {
        inString = true;
      } else if (ch == '{' || ch == '[') {
        depth++;
        if (depth > deepest) deepest = depth;
        if (deepest > MAX_DEPTH) break;
      } else if (ch == '}' || ch == ']') {
        depth--;
      } else if (ch == ':') {
        keys++;
        if (keys > MAX_KEYS) break;
      }
    }
    if (deepest > MAX_DEPTH) return Problem.TOO_DEEP;
    if (keys > MAX_KEYS) return Problem.TOO_MANY_KEYS;
    return null;
  }
}
