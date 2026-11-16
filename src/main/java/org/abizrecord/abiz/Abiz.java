package org.abizrecord.abiz;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * ABIZ (Agentic Business Record) 1.1 for Java: the entry points. See {@link Resolver} for
 * resolution with your own DNS or HTTP, and the README for what is and is not checked.
 *
 * <p>A resolved record is the publisher's own claim, signed with the key that DNS (or the domain's
 * well-known file) vouches for. Nothing here checks a company register or calls
 * {@code mcp_server_url}.
 */
public final class Abiz {
  private Abiz() {}

  /** This library's version. */
  public static final String VERSION = "2026.1116.1";
  /** The ABIZ revision implemented. */
  public static final String ABIZ_REVISION = "1.1";
  /** The test-vector format this library passes. */
  public static final int TEST_VECTOR_FORMAT = 1;
  /** The {@code User-Agent} the guarded fetch sends. */
  public static final String USER_AGENT = "abiz-java/" + VERSION + " (+https://abizrecord.org)";
  /** The {@code $id} of the bundled record schema. */
  public static final String SCHEMA_ID = "https://abizrecord.org/schema/abiz-business-record-v1.1.schema.json";
  /** SHA-256 of the bundled {@code abiz-business-record-v1.1.schema.json}. */
  public static final String SCHEMA_SHA256 = "3658f17f00c238b8c948fdfb447b509c5d055dd778ebd335495da05c3150ff24";
  /** SHA-256 of the bundled {@code abiz-well-known-v1.1.schema.json}. */
  public static final String WELL_KNOWN_SCHEMA_SHA256 = "5fe7da6fb5b6b262281402ab9dd9b46c018bf9df766203928e4e1a334cc3d741";
  /** SHA-256 of the bundled {@code iso3166.json} (LGPL-2.1). */
  public static final String ISO3166_SHA256 = "0aa5112c46bc2b3efb254ea9536b3cf2977c73d48149aefcd8bc20df995e5527";

  private static final class Default {
    static final Resolver RESOLVER = Resolver.create();
  }

  /**
   * Resolve a domain on the network with the default resolver (system DNS through dnsjava, and the
   * guarded HTTPS fetch).
   *
   * @param domain a host name such as {@code example.com}
   * @return the result
   */
  public static ResolveResult resolve(String domain) {
    return Default.RESOLVER.resolve(domain);
  }

  /**
   * Resolve the host of a website address on the network with the default resolver.
   *
   * @param website a website address such as {@code https://www.example.com/}
   * @return the result
   */
  public static ResolveResult resolveWebsite(String website) {
    return Default.RESOLVER.resolveWebsite(website);
  }

  /**
   * Parse one {@code _abiz} TXT value.
   *
   * @param value the value, its character-strings joined
   * @return the assertion ({@code h}, {@code k}, {@code p}, unknown tags) or an error code
   */
  public static AssertionResult parseAssertion(String value) {
    return Assertions.parse(value);
  }

  /**
   * Check a record offline against the queried domain and an assertion, in the resolver's order:
   * I-JSON and limits, JSON Schema, semantic checks, {@code identity_host}, {@code domains}, the
   * business key, {@code public_key} and the signature.
   *
   * @param recordText the record as served
   * @param domain the queried domain, normalised (lower case, no trailing dot)
   * @param assertion the assertion that pointed at the record
   * @return null when the record is accepted, else the first failing code
   */
  public static ErrorCode checkRecord(String recordText, String domain, Assertion assertion) {
    return RecordValidator.check(recordText, domain, assertion).code();
  }

  /**
   * As {@link #checkRecord(String, String, Assertion)}, with the assertion as its TXT text. An
   * assertion that does not parse gives its own code.
   *
   * @param recordText the record as served
   * @param domain the queried domain, normalised
   * @param assertionValue the {@code _abiz} TXT value
   * @return null when the record is accepted, else the first failing code
   */
  public static ErrorCode checkRecord(String recordText, String domain, String assertionValue) {
    AssertionResult parsed = Assertions.parse(assertionValue);
    if (!parsed.ok()) return parsed.code();
    return checkRecord(recordText, domain, parsed.assertion());
  }

  /**
   * As {@link #checkRecord(String, String, Assertion)}, with the problems found and the parsed record.
   *
   * @param recordText the record as served
   * @param domain the queried domain, normalised
   * @param assertion the assertion that pointed at the record
   * @return the outcome
   */
  public static RecordCheck checkRecordDetailed(String recordText, String domain, Assertion assertion) {
    return RecordValidator.check(recordText, domain, assertion);
  }

  /**
   * Check a record's {@code public_key} against {@code p}, then its signature.
   *
   * @param record the record
   * @param p the {@code p} tag
   * @return null when both hold, else {@link ErrorCode#PUBLIC_KEY_MISMATCH} or {@link ErrorCode#SIGNATURE_INVALID}
   */
  public static ErrorCode verifySignature(JsonNode record, String p) {
    return Signatures.verify(record, p);
  }

  /**
   * RFC 8785 canonical JSON of a value.
   *
   * @param value a JSON value
   * @return its canonical text
   * @throws Jcs.JcsException when the value is not I-JSON
   */
  public static String canonicalize(JsonNode value) {
    return Jcs.canonicalize(value);
  }

  /**
   * RFC 8785 canonical JSON of a JSON text.
   *
   * @param jsonText a JSON text
   * @return its canonical text
   * @throws IllegalArgumentException when the text is not I-JSON (including a repeated member name)
   * @throws Jcs.JcsException when it holds a value RFC 8785 cannot canonicalise
   */
  public static String canonicalize(String jsonText) {
    return Jcs.canonicalize(parseJson(jsonText));
  }

  /**
   * Parse an I-JSON text: a repeated member name or trailing content is an error. No size limits.
   *
   * @param jsonText a JSON text
   * @return the value
   * @throws IllegalArgumentException when the text is not I-JSON
   */
  public static JsonNode parseJson(String jsonText) {
    StrictJson.Result result = StrictJson.parseUnlimited(jsonText);
    if (!result.ok()) {
      throw new IllegalArgumentException(result.problem() == StrictJson.Problem.DUPLICATE_MEMBER
          ? "the JSON text repeats a member name" : "not a JSON text");
    }
    return result.value();
  }

  /**
   * A producer helper: the record with {@code public_key} and {@code signature} set.
   *
   * @param record the record, without or with an old signature
   * @param privateKeySeed the 32-byte Ed25519 private key (seed)
   * @return a signed copy; the input is not modified
   */
  public static ObjectNode signRecord(ObjectNode record, byte[] privateKeySeed) {
    return Signatures.sign(record, privateKeySeed);
  }
}
