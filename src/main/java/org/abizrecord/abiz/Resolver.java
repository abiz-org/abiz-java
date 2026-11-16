package org.abizrecord.abiz;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;
import org.abizrecord.abiz.net.DnsjavaTxtLookup;
import org.abizrecord.abiz.net.GuardedHttpsFetcher;

/**
 * The ABIZ resolution algorithm (SPEC sections 3 to 6; resolver specification section 4): input,
 * one TXT query, selection, the assertion, the well-known fallback, one guarded fetch of the
 * record, and the record checks. DNS and HTTP go through the {@link TxtLookup} and
 * {@link RecordFetcher} ports. The resolver never contacts {@code mcp_server_url} or any other
 * URL in the record, and never checks a company register.
 *
 * <p>Instances are immutable and thread-safe when their ports are.
 */
public final class Resolver {
  private static final Pattern JSON_SUBTYPE = Pattern.compile("^application/[a-z0-9.+-]+\\+json\\z");

  private final TxtLookup dns;
  private final RecordFetcher http;

  /**
   * A resolver with the given ports.
   *
   * @param dns the TXT lookup
   * @param http the guarded fetch
   */
  public Resolver(TxtLookup dns, RecordFetcher http) {
    this.dns = Objects.requireNonNull(dns, "dns");
    this.http = Objects.requireNonNull(http, "http");
  }

  /**
   * A resolver on the network: the system's DNS servers through dnsjava, and the guarded HTTPS
   * fetch.
   *
   * @return a resolver
   */
  public static Resolver create() {
    DnsjavaTxtLookup dns = new DnsjavaTxtLookup();
    return new Resolver(dns, new GuardedHttpsFetcher(dns.addressResolver()));
  }

  /**
   * Resolve a domain.
   *
   * @param domain a host name such as {@code example.com}
   * @return the result
   */
  public ResolveResult resolve(String domain) {
    return resolve(domain, null);
  }

  /**
   * Resolve the host of a website address. The path is ignored; {@code www.} is not stripped.
   *
   * @param website a website address such as {@code https://www.example.com/about}
   * @return the result
   */
  public ResolveResult resolveWebsite(String website) {
    return resolve(null, website);
  }

  /**
   * Resolve exactly one of a domain and a website. Both, or neither, is {@code invalid_input}.
   *
   * @param domain a host name, or null
   * @param website a website address, or null
   * @return the result
   */
  public ResolveResult resolve(String domain, String website) {
    Hosts.NormalisedInput input = Hosts.normaliseInput(domain, website);
    if (!input.ok()) {
      String given = domain != null && !domain.isEmpty() ? (domain.length() > 260 ? domain.substring(0, 260) : domain) : null;
      return new ResolveResult(input.error().status(), input.error(), input.message(), input.error().retryable(),
          List.of(), null, given, null, List.of());
    }
    return new Run(input.domain()).run();
  }

  /** One resolution's mutable state. */
  private final class Run {
    final String domain;
    final String owner;
    String method = "dns_txt";
    String dnsValue;
    List<String> dnsValues = List.of();
    String recordUrl;
    String wellKnown = "not_checked";
    String wellKnownUrl;
    final List<Warning> warnings = new ArrayList<>();

    Run(String domain) {
      this.domain = domain;
      this.owner = "_abiz." + domain;
    }

    ResolveResult finish(Status status, ErrorCode code, String message, List<Problem> details, JsonNode record) {
      List<Problem> capped = details == null ? List.of()
          : details.size() > RecordValidator.MAX_PROBLEMS ? details.subList(0, RecordValidator.MAX_PROBLEMS) : details;
      Discovery discovery = new Discovery(method, owner, dnsValue, dnsValues, recordUrl, wellKnown, wellKnownUrl);
      return new ResolveResult(status, code, message, code != null && code.retryable(), capped, record, domain, discovery, warnings);
    }

    ResolveResult fail(ErrorCode code, List<Problem> details, String message) {
      return finish(code.status(), code, message != null ? message : code.defaultMessage(), details, null);
    }

    ResolveResult fail(ErrorCode code, List<Problem> details) {
      return fail(code, details, null);
    }

    ResolveResult run() {
      // Step 2: one TXT query.
      TxtLookup.Result lookup;
      try {
        lookup = dns.lookup(owner);
      } catch (RuntimeException e) {
        lookup = new TxtLookup.Failure(TxtLookup.Reason.NETWORK);
      }
      if (lookup instanceof TxtLookup.Failure) {
        TxtLookup.Reason reason = ((TxtLookup.Failure) lookup).reason();
        boolean timeout = reason == TxtLookup.Reason.TIMEOUT || reason == TxtLookup.Reason.NETWORK;
        return fail(timeout ? ErrorCode.DNS_TIMEOUT : ErrorCode.DNS_FAILURE, null);
      }
      List<String> values = lookup instanceof TxtLookup.Answer ? ((TxtLookup.Answer) lookup).values() : List.of();
      List<String> matching = new ArrayList<>();
      for (String value : values) if (Assertions.isAssertion(value)) matching.add(value);

      // Step 3: select.
      if (matching.size() > 1) {
        dnsValues = matching;
        return fail(ErrorCode.MULTIPLE_TXT, null);
      }
      Assertion assertion;
      if (matching.size() == 1) {
        // Step 4. A malformed assertion is invalid: the well-known file is not used.
        dnsValue = matching.get(0);
        AssertionResult parsed = Assertions.parse(dnsValue);
        if (!parsed.ok()) return fail(parsed.code(), List.of(new Problem(owner, parsed.message())));
        assertion = parsed.assertion();
      } else if (values.stream().anyMatch(Assertions::isNearMiss)) {
        return fail(ErrorCode.BAD_POINTER, List.of(new Problem(owner,
            "A TXT record looks like an ABIZ assertion, but its first tag is not exactly v=abiz1 (check case, spaces and quotes).")));
      } else {
        // Step 5: no v=abiz1 value; the well-known file may carry the same tags.
        wellKnownUrl = "https://" + domain + "/.well-known/abiz.json";
        RecordFetcher.Outcome file = fetch(wellKnownUrl);
        if (file instanceof RecordFetcher.Timeout) {
          wellKnown = "unavailable";
          return fail(ErrorCode.UPSTREAM_TIMEOUT, null);
        }
        if (file instanceof RecordFetcher.Network || file instanceof RecordFetcher.DnsError) {
          wellKnown = "unavailable";
          return fail(ErrorCode.ORIGIN_UNAVAILABLE, null,
              "The well-known file could not be fetched. This does not establish that no ABIZ record exists.");
        }
        if (file instanceof RecordFetcher.Response) {
          int status = ((RecordFetcher.Response) file).status();
          if (status == 408 || status == 429 || status >= 500) {
            wellKnown = "unavailable";
            return fail(ErrorCode.ORIGIN_UNAVAILABLE, null,
                "The well-known file host answered HTTP " + status + ". This does not establish that no ABIZ record exists.");
          }
        }
        Assertion fromFile = null;
        String invalid = null;
        if (file instanceof RecordFetcher.Response && ((RecordFetcher.Response) file).status() == 200) {
          RecordFetcher.Response response = (RecordFetcher.Response) file;
          String type = mediaType(response.contentType());
          if (response.body() == null) {
            invalid = "The well-known file is larger than this library accepts (64 KiB).";
          } else if (!isJsonType(type)) {
            invalid = "The well-known file was not application/json.";
          } else {
            StrictJson.Result json = StrictJson.parse(response.body());
            if (!json.ok()) {
              invalid = "The well-known file is not JSON.";
            } else {
              String[] tags = new String[1];
              invalid = wellKnownTags(json.value(), tags);
              if (invalid == null) {
                AssertionResult parsed = Assertions.parse(tags[0]);
                if (parsed.ok()) fromFile = parsed.assertion();
                else invalid = parsed.message();
              }
            }
          }
        }
        if (fromFile == null) {
          wellKnown = invalid != null ? "invalid" : "absent";
          String apex = Hosts.apexSuggestion(domain);
          if (apex != null) {
            warnings.add(new Warning("try_apex", "Nothing is published at " + owner + ". " + apex
                + " was not checked and is a different domain; query it separately if that is the business's domain.", apex));
          }
          return fail(ErrorCode.MISSING_TXT, invalid != null ? List.of(new Problem(wellKnownUrl, invalid)) : null);
        }
        method = "well_known";
        wellKnown = "used";
        assertion = fromFile;
      }

      // Step 6: fetch https://<h>?format=json.
      recordUrl = "https://" + assertion.h() + "?format=json";
      RecordFetcher.Outcome fetched = fetch(recordUrl);
      if (fetched instanceof RecordFetcher.Blocked) {
        return fail(ErrorCode.UNSAFE_HOST, List.of(new Problem("h", ((RecordFetcher.Blocked) fetched).message())));
      }
      if (fetched instanceof RecordFetcher.NoAddress) {
        return fail(ErrorCode.FETCH_FAILED, List.of(new Problem("h", "The record host has no public A or AAAA address.")));
      }
      if (fetched instanceof RecordFetcher.DnsError) {
        return fail(ErrorCode.ORIGIN_UNAVAILABLE, null,
            "The record host's address could not be looked up. This does not establish that the record is missing.");
      }
      if (fetched instanceof RecordFetcher.Timeout) return fail(ErrorCode.UPSTREAM_TIMEOUT, null);
      if (fetched instanceof RecordFetcher.Network) {
        return fail(ErrorCode.ORIGIN_UNAVAILABLE, null,
            "The connection to the record host failed (network or TLS). This does not establish that the record is missing.");
      }
      RecordFetcher.Response response = (RecordFetcher.Response) fetched;
      int status = response.status();
      if (status == 408 || status == 429 || status >= 500) {
        return fail(ErrorCode.ORIGIN_UNAVAILABLE, null,
            "The record host answered HTTP " + status + ". This does not establish that the record is missing.");
      }
      if (status >= 300 && status < 400) {
        return fail(ErrorCode.FETCH_FAILED, List.of(new Problem("h", "The record host answered with a redirect (HTTP " + status
            + "). Redirects are not followed: serve the record at the exact h= address.")));
      }
      if (status != 200) {
        return fail(ErrorCode.FETCH_FAILED, List.of(new Problem("h",
            "The record host answered HTTP " + status + "; ABIZ needs 200 with the JSON record.")));
      }
      if (response.body() == null) return fail(ErrorCode.RECORD_TOO_LARGE, null);
      String contentType = response.contentType();
      boolean json = contentType != null && isJsonType(mediaType(contentType));
      if (contentType != null && !contentType.isEmpty() && !json) {
        String type = mediaType(contentType);
        if (!type.equals("text/plain")) {
          return fail(ErrorCode.NOT_JSON, List.of(new Problem("h",
              "The record host answered " + (type.length() > 80 ? type.substring(0, 80) : type) + " to Accept: application/json.")));
        }
      }
      if (!json) {
        warnings.add(new Warning("content_type", "The record was served without a JSON content type; it was read as JSON anyway.", null));
      }

      // Steps 7 to 9: parse, check, verify.
      RecordCheck check = RecordValidator.check(response.body(), domain, assertion);
      if (!check.ok()) return fail(check.code(), check.details());
      return finish(Status.RESOLVED, null, null, List.of(), check.record());
    }

    RecordFetcher.Outcome fetch(String url) {
      try {
        RecordFetcher.Outcome outcome = http.fetch(url);
        return outcome == null ? new RecordFetcher.Network() : outcome;
      } catch (RuntimeException e) {
        return new RecordFetcher.Network();
      }
    }
  }

  /** SPEC section 3.4.2: the file's {@code v k h p} members as an assertion's text. Unknown members are ignored. */
  private static String wellKnownTags(JsonNode doc, String[] out) {
    if (doc == null || !doc.isObject()) return "The well-known file must be a JSON object.";
    for (String member : List.of("v", "k", "h", "p")) {
      if (doc.has(member) && !doc.get(member).isTextual()) return "Well-known member " + member + " must be a string.";
    }
    if (!doc.has("v") || !doc.get("v").textValue().equals("abiz1")) return "The well-known file must have \"v\": \"abiz1\".";
    for (String member : List.of("h", "p")) {
      if (!doc.has(member)) return "The well-known file is missing " + member + ".";
    }
    StringBuilder tags = new StringBuilder("v=abiz1");
    for (String member : List.of("k", "h", "p")) {
      if (!doc.has(member)) continue;
      String value = doc.get(member).textValue();
      if (value.isEmpty() || Pattern.compile("[" + Text.JS_SPACE_CLASS_BODY + ";]").matcher(value).find()) {
        return "Well-known member " + member + " must be a non-empty value without whitespace or ';'.";
      }
      tags.append(';').append(member).append('=').append(value);
    }
    out[0] = tags.toString();
    return null;
  }

  private static String mediaType(String contentType) {
    if (contentType == null) return "";
    int semi = contentType.indexOf(';');
    return Text.jsTrim(semi < 0 ? contentType : contentType.substring(0, semi)).toLowerCase(Locale.ROOT);
  }

  private static boolean isJsonType(String type) {
    return type.equals("application/json") || JSON_SUBTYPE.matcher(type).matches();
  }
}
