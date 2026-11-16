package org.abizrecord.abiz;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestFactory;

/** Every case of every vector file (format 1), run exactly. */
class VectorTest {
  private static final java.util.Map<String, Integer> PASSED = new java.util.concurrent.ConcurrentSkipListMap<>();

  /** Counts a case as passed when its checks complete without failing. */
  private static org.junit.jupiter.api.function.Executable counted(String file, org.junit.jupiter.api.function.Executable body) {
    return () -> {
      body.execute();
      PASSED.merge(file, 1, Integer::sum);
    };
  }

  @org.junit.jupiter.api.AfterAll
  static void summary() {
    StringBuilder line = new StringBuilder("ABIZ test vectors (format 1) passed:");
    PASSED.forEach((file, n) -> line.append(' ').append(file).append(' ').append(n).append(','));
    line.setLength(line.length() - 1);
    System.out.println(line.append(". Total ").append(PASSED.values().stream().mapToInt(Integer::intValue).sum()).append('.'));
  }

  private static Stream<JsonNode> cases(JsonNode root, String member) {
    return StreamSupport.stream(root.get(member).spliterator(), false);
  }

  private static String label(JsonNode c, String fallback) {
    String name = Vectors.text(c, "name");
    return name != null ? name : fallback;
  }

  @Nested
  @DisplayName("assertions.json")
  class AssertionsJson {
    @TestFactory
    Stream<DynamicTest> assertions() {
      return cases(Vectors.load("assertions.json"), "cases").map(c -> dynamicTest("assertions: " + label(c, ""), counted("assertions.json", () -> {
        String value = c.get("value").asText();
        assertEquals(c.get("is_assertion").asBoolean(), Assertions.isAssertion(value), "is_assertion");
        AssertionResult parsed = Assertions.parse(value);
        assertEquals(c.get("ok").asBoolean(), parsed.ok(), () -> "ok: " + parsed);
        if (parsed.ok()) {
          assertEquals(c.get("h").asText(), parsed.assertion().h(), "h");
          assertEquals(Vectors.text(c, "k"), parsed.assertion().k(), "k");
          assertEquals(c.get("p").asText(), parsed.assertion().p(), "p");
        } else {
          assertEquals(c.get("code").asText(), parsed.code().code(), "code");
        }
      })));
    }
  }

  @Nested
  @DisplayName("public-keys.json")
  class PublicKeysJson {
    @TestFactory
    Stream<DynamicTest> publicKeys() {
      return cases(Vectors.load("public-keys.json"), "cases").map(c -> dynamicTest("public-keys: " + c.get("value").asText(), counted("public-keys.json", () -> assertEquals(c.get("ok").asBoolean(), Assertions.isPublicKey(c.get("value").asText())))));
    }
  }

  @Nested
  @DisplayName("hosts.json identity")
  class HostsJsonIdentity {
    @TestFactory
    Stream<DynamicTest> hostIdentity() {
      return cases(Vectors.load("hosts.json"), "identity").map(c -> dynamicTest("hosts identity: " + c.get("value").asText(), counted("hosts.json (identity)", () -> assertEquals(Vectors.text(c, "canonical"), Hosts.identityParts(c.get("value").asText())))));
    }
  }

  @Nested
  @DisplayName("hosts.json inputs")
  class HostsJsonInputs {
    @TestFactory
    Stream<DynamicTest> hostInputs() {
      return cases(Vectors.load("hosts.json"), "inputs").map(c -> dynamicTest("hosts inputs: " + c.get("input"), counted("hosts.json (inputs)", () -> {
        JsonNode input = c.get("input");
        Hosts.NormalisedInput out = Hosts.normaliseInput(Vectors.text(input, "domain"), Vectors.text(input, "website"));
        assertEquals(c.get("ok").asBoolean(), out.ok(), () -> "ok: " + out);
        if (out.ok()) assertEquals(c.get("domain").asText(), out.domain());
        else assertEquals(c.get("code").asText(), out.error().code());
      })));
    }
  }

  @Nested
  @DisplayName("addresses.json")
  class AddressesJson {
    @TestFactory
    Stream<DynamicTest> addresses() {
      return cases(Vectors.load("addresses.json"), "cases").map(c -> dynamicTest("addresses: " + c.get("address").asText(), counted("addresses.json", () -> assertEquals(c.get("public").asBoolean(), Addresses.isPublic(c.get("address").asText())))));
    }
  }

  @Nested
  @DisplayName("jcs.json")
  class JcsJson {
    @TestFactory
    Stream<DynamicTest> jcs() {
      return cases(Vectors.load("jcs.json"), "cases").map(c -> dynamicTest("jcs: " + label(c, ""), counted("jcs.json", () -> {
        String out = Abiz.canonicalize(c.get("input").asText());
        // Byte for byte: compare the UTF-8 encodings.
        assertEquals(HexFormat.of().formatHex(c.get("output").asText().getBytes(StandardCharsets.UTF_8)),
            HexFormat.of().formatHex(out.getBytes(StandardCharsets.UTF_8)), () -> "got " + out);
      })));
    }
  }

  @Nested
  @DisplayName("signing.json")
  class SigningJson {
    @TestFactory
    Stream<DynamicTest> signing() {
      JsonNode root = Vectors.load("signing.json");
      List<DynamicTest> tests = new ArrayList<>();
      for (JsonNode key : root.get("test_keys")) {
        tests.add(dynamicTest("signing: " + key.get("name").asText() + " public key", counted("signing.json", () -> assertEquals(
            key.get("public_key").asText(), Signatures.publicKeyOf(HexFormat.of().parseHex(key.get("seed_hex").asText()))))));
      }
      cases(root, "cases").forEach(c -> tests.add(dynamicTest("signing: " + label(c, ""), counted("signing.json", () -> {
        JsonNode record = Abiz.parseJson(c.get("record_text").asText());
        String input = new String(Signatures.signingInput(record), StandardCharsets.UTF_8);
        assertEquals(c.get("signing_input").asText(), input, "signing_input");
        ErrorCode verified = Abiz.verifySignature(record, record.get("public_key").asText());
        assertEquals(c.get("verifies").asBoolean(), verified == null, () -> "verify: " + verified);
      }))));
      return tests.stream();
    }
  }

  @Nested
  @DisplayName("records.json")
  class RecordsJson {
    @TestFactory
    Stream<DynamicTest> records() {
      return cases(Vectors.load("records.json"), "cases").map(c -> dynamicTest("records: " + label(c, ""), counted("records.json", () -> {
        ErrorCode code = Abiz.checkRecord(c.get("record_text").asText(), c.get("domain").asText(), c.get("assertion").asText());
        String detail = String.valueOf(Abiz.checkRecordDetailed(c.get("record_text").asText(), c.get("domain").asText(),
            Abiz.parseAssertion(c.get("assertion").asText()).assertion()).details());
        assertEquals(Vectors.text(c, "expect"), code == null ? null : code.code(), () -> "details: " + detail);
      })));
    }
  }

  @Nested
  @DisplayName("resolution.json")
  class ResolutionJson {
    @TestFactory
    Stream<DynamicTest> resolution() {
      return cases(Vectors.load("resolution.json"), "cases").map(c -> dynamicTest("resolution: " + label(c, ""), counted("resolution.json", () -> {
        StubDns dns = new StubDns(c.get("dns"));
        StubHttp http = new StubHttp(c.get("http"));
        JsonNode input = c.get("input");
        ResolveResult r = new Resolver(dns, http).resolve(Vectors.text(input, "domain"), Vectors.text(input, "website"));
        JsonNode e = c.get("expect");
        assertEquals(e.get("status").asText(), r.status().wireName(), "status");
        assertEquals(Vectors.text(e, "code"), r.code() == null ? null : r.code().code(), () -> "code; details " + r.details());
        assertEquals(e.get("retryable").asBoolean(), r.retryable(), "retryable");
        if (e.has("method")) {
          assertNotNull(r.discovery(), "discovery");
          assertEquals(e.get("method").asText(), r.discovery().method(), "method");
          assertEquals(e.get("well_known").asText(), r.discovery().wellKnown(), "well_known");
        } else {
          assertNull(r.discovery(), "discovery");
        }
        assertEquals(Vectors.text(e, "dns_value"), r.discovery() == null ? null : r.discovery().dnsValue(), "dns_value");
        assertEquals(Vectors.text(e, "domain"), r.domain(), "domain");
        List<String> expectedWarnings = new ArrayList<>();
        for (JsonNode w : e.get("warnings")) expectedWarnings.add(w.get("code").asText() + "|" + Vectors.text(w, "domain"));
        List<String> warnings = new ArrayList<>();
        for (Warning w : r.warnings()) warnings.add(w.code() + "|" + w.domain());
        assertEquals(expectedWarnings, warnings, "warnings");
        assertEquals(e.get("record_returned").asBoolean(), r.record() != null, "record_returned");
        if (r.record() != null) assertTrue(r.resolved());
        else assertFalse(r.resolved());
        List<String> expectedQueries = new ArrayList<>();
        e.get("dns_queries").forEach(q -> expectedQueries.add(q.asText()));
        List<String> expectedFetches = new ArrayList<>();
        e.get("fetches").forEach(f -> expectedFetches.add(f.asText()));
        assertEquals(expectedQueries, dns.queried, "dns_queries");
        assertEquals(expectedFetches, http.fetched, "fetches");
      })));
    }
  }

  /** The vectors' fake DNS: an owner name maps to its answer; absent is NXDOMAIN. */
  static final class StubDns implements TxtLookup {
    final JsonNode table;
    final List<String> queried = new ArrayList<>();

    StubDns(JsonNode table) {
      this.table = table;
    }

    @Override
    public Result lookup(String name) {
      queried.add(name);
      JsonNode stub = table.get(name);
      if (stub == null) return new NxDomain();
      switch (stub.get("kind").asText()) {
        case "answer": {
          List<String> values = new ArrayList<>();
          stub.get("values").forEach(v -> values.add(v.asText()));
          return new Answer(values);
        }
        case "nxdomain":
          return new NxDomain();
        case "nodata":
          return new NoData();
        case "error":
          return new Failure(Reason.valueOf(stub.get("reason").asText().toUpperCase(java.util.Locale.ROOT)));
        default:
          throw new IllegalArgumentException("unknown DNS stub " + stub);
      }
    }
  }

  /** The vectors' fake fetch: the exact URL maps to its outcome; absent is a 404. */
  static final class StubHttp implements RecordFetcher {
    final JsonNode table;
    final List<String> fetched = new ArrayList<>();

    StubHttp(JsonNode table) {
      this.table = table;
    }

    @Override
    public Outcome fetch(String url) {
      fetched.add(url);
      JsonNode stub = table.get(url);
      if (stub == null) return new Response(404, "text/plain", "Not found");
      switch (stub.get("kind").asText()) {
        case "response":
          return new Response(stub.get("status").asInt(), Vectors.text(stub, "content_type"), Vectors.text(stub, "body"));
        case "blocked":
          return new Blocked("stub: refused address");
        case "no_address":
          return new NoAddress();
        case "dns_error":
          return new DnsError();
        case "timeout":
          return new Timeout();
        case "network":
          return new Network();
        default:
          throw new IllegalArgumentException("unknown HTTP stub " + stub);
      }
    }
  }

}
