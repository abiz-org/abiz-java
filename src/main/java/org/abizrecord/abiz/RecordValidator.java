package org.abizrecord.abiz;

import com.fasterxml.jackson.databind.JsonNode;
import com.networknt.schema.Error;
import com.networknt.schema.Schema;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.SchemaRegistryConfig;
import com.networknt.schema.dialect.Dialect;
import com.networknt.schema.dialect.Dialects;
import com.networknt.schema.path.PathType;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Record conformance (SPEC section 4): the pinned JSON Schema 2020-12 with formats asserted, then
 * the checks JSON Schema cannot express, then the links to the assertion and the queried domain,
 * then the signature. A port of {@code validate.ts}, {@code signature.ts} and the order of checks
 * in {@code resolve.ts}.
 */
final class RecordValidator {
  private RecordValidator() {}

  static final int MAX_PROBLEMS = 25;

  private static final Schema SCHEMA = loadSchema();

  private static Schema loadSchema() {
    SchemaRegistryConfig config = SchemaRegistryConfig.builder()
        .formatAssertionsEnabled(true)
        .losslessNarrowing(true)
        .pathType(PathType.JSON_POINTER)
        .regularExpressionFactory(EcmaRegexFactory.INSTANCE)
        .build();
    // Draft 2020-12, with the five formats the schema uses defined as the reference defines them.
    Dialect dialect = Dialect.builder(Dialects.getDraft202012()).formats(ReferenceFormats.all()).build();
    SchemaRegistry registry = SchemaRegistry.withDialect(dialect,
        builder -> builder.schemaRegistryConfig(config).schemaLoader(loader -> loader.fetchRemoteResources(false)));
    try (InputStream in = Bundled.open(Bundled.RECORD_SCHEMA)) {
      return registry.getSchema(in);
    } catch (IOException e) {
      throw new UncheckedIOException("cannot read the bundled schema", e);
    }
  }

  /** The whole offline check, in the reference order. */
  static RecordCheck check(String recordText, String domain, Assertion assertion) {
    StrictJson.Result parsed = StrictJson.parse(recordText);
    if (!parsed.ok()) {
      switch (parsed.problem()) {
        case TOO_DEEP:
        case TOO_MANY_KEYS:
          return new RecordCheck(ErrorCode.RECORD_TOO_LARGE, List.of(new Problem("$",
              "The record nests deeper than " + StrictJson.MAX_DEPTH + " or has more than " + StrictJson.MAX_KEYS + " members.")), null);
        case DUPLICATE_MEMBER:
          return new RecordCheck(ErrorCode.NOT_JSON, List.of(new Problem("$",
              "The record repeats a member name; ABIZ records are I-JSON (RFC 7493), so it is rejected.")), null);
        default:
          return new RecordCheck(ErrorCode.NOT_JSON, List.of(new Problem("$", "The record is not JSON.")), null);
      }
    }
    return check(parsed.value(), domain, assertion);
  }

  /** The checks after parsing. */
  static RecordCheck check(JsonNode record, String domain, Assertion assertion) {
    List<Problem> schemaProblems = validateSchema(record);
    if (!schemaProblems.isEmpty()) return new RecordCheck(ErrorCode.SCHEMA_INVALID, schemaProblems, record);
    List<Problem> conformance = new ArrayList<>();
    List<Problem> keyProblems = new ArrayList<>();
    semanticProblems(record, conformance, keyProblems);
    String identity = Hosts.identityParts(text(record, "identity_host"));
    boolean identityMatches = identity != null && identity.equals(assertion.h());
    Set<String> declared = new HashSet<>();
    for (JsonNode d : iterable(record.get("domains"))) {
      if (d.isTextual()) {
        String value = d.textValue().toLowerCase(Locale.ROOT);
        declared.add(value.endsWith(".") ? value.substring(0, value.length() - 1) : value);
      }
    }
    boolean domainClaimed = declared.contains(domain);
    JsonNode key = record.get("business_key");
    if (assertion.k() != null && key != null && key.isTextual() && !BusinessKey.same(assertion.k(), key.textValue())) {
      keyProblems.add(new Problem("/business_key", "The DNS k= tag and the record business_key differ."));
    } else if (key == null && assertion.k() != null) {
      keyProblems.add(new Problem("/business_key", "The DNS assertion has k= but the record has no business_key."));
    }
    if (!conformance.isEmpty()) {
      List<Problem> all = new ArrayList<>(conformance);
      all.addAll(keyProblems);
      return new RecordCheck(ErrorCode.SCHEMA_INVALID, all, record);
    }
    if (!identityMatches) {
      return new RecordCheck(ErrorCode.IDENTITY_HOST_MISMATCH, List.of(new Problem("/identity_host",
          "identity_host must equal the DNS h= value (" + assertion.h() + ") exactly, path included.")), record);
    }
    if (!domainClaimed) {
      return new RecordCheck(ErrorCode.DOMAIN_NOT_CLAIMED, List.of(new Problem("/domains",
          "domains must include " + domain + ", the domain whose _abiz record points here.")), record);
    }
    if (!keyProblems.isEmpty()) return new RecordCheck(ErrorCode.BUSINESS_KEY_MISMATCH, keyProblems, record);
    Problem signature = Signatures.check(record, assertion.p());
    if (signature != null) {
      ErrorCode code = signature.path().equals("/public_key") ? ErrorCode.PUBLIC_KEY_MISMATCH : ErrorCode.SIGNATURE_INVALID;
      return new RecordCheck(code, List.of(signature), record);
    }
    return new RecordCheck(null, List.of(), record);
  }

  static List<Problem> validateSchema(JsonNode record) {
    List<Error> errors = SCHEMA.validate(record);
    if (errors.isEmpty()) return List.of();
    Set<String> seen = new LinkedHashSet<>();
    List<Problem> out = new ArrayList<>();
    for (Error error : errors) {
      String path = error.getInstanceLocation() == null ? "" : error.getInstanceLocation().toString();
      if (path.isEmpty() || path.equals("#")) path = "$";
      if (path.startsWith("#")) path = path.substring(1);
      String message = String.valueOf(error.getMessage());
      if (message.length() > 300) message = message.substring(0, 300);
      if (seen.add(path + "\n" + message)) out.add(new Problem(path, message));
    }
    return out.isEmpty() ? List.of(new Problem("$", "The record does not match the ABIZ schema.")) : out;
  }

  // ------------------------------------------------------------------------------------------
  // Semantic checks (SPEC section 4.7), all reported as schema_invalid, except business key
  // problems, reported as business_key_mismatch.

  private static final List<String> DAYS = List.of("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday");
  private static final Set<String> FORBIDDEN_KEYS = Set.of("recent_posts", "contact_email", "contact_phone");
  private static final Pattern HH_MM = Pattern.compile("^(\\d{2}):(\\d{2})\\z");
  private static final Pattern HTTP_PREFIX = Pattern.compile("^https?://", Pattern.CASE_INSENSITIVE);
  private static final Set<String> TIME_ZONES = Set.copyOf(ZoneId.getAvailableZoneIds());

  static void semanticProblems(JsonNode record, List<Problem> conformance, List<Problem> businessKey) {
    if (Hosts.identityParts(text(record, "identity_host")) == null) {
      conformance.add(new Problem("/identity_host", "identity_host is not a valid DNS host name with an optional path."));
    }
    int i = 0;
    for (JsonNode domain : iterable(record.get("domains"))) {
      if (domain.isTextual() && !Hosts.isSafeHost(domain.textValue())) {
        conformance.add(new Problem("/domains/" + i, "\"" + clip(domain.textValue(), 80) + "\" is not a valid domain name."));
      }
      i++;
    }
    String countryCode = nestedCode(record.get("country"));
    if (countryCode == null) {
      conformance.add(new Problem("/country", "country must be an object with code and name."));
    } else {
      String problem = countryCodeProblem(countryCode);
      if (problem != null) conformance.add(new Problem("/country/code", problem));
    }
    JsonNode rootRegion = record.get("region");
    if (rootRegion != null && rootRegion.isObject() && text(rootRegion, "code") != null && countryCode != null) {
      String problem = BusinessKey.regionCodeProblem(text(rootRegion, "code"), countryCode);
      if (problem != null) conformance.add(new Problem("/region/code", problem));
    }
    for (String key : List.of("website", "logo_url", "mcp_server_url", "blog_url", "rss_url")) {
      String value = text(record, key);
      if (value != null && !Hosts.isSafeHttpsUrl(value)) {
        conformance.add(new Problem("/" + key, key + " must be an https URL with a public DNS host name."));
      }
    }
    for (String collection : List.of("services", "links")) {
      JsonNode items = record.get(collection);
      if (items == null || !items.isArray()) continue;
      for (int j = 0; j < items.size(); j++) {
        String url = text(items.get(j), "url");
        if (url != null && !Hosts.isSafeHttpsUrl(url)) {
          conformance.add(new Problem("/" + collection + "/" + j + "/url", "url must be an https URL with a public DNS host name."));
        }
      }
    }
    forbiddenKeyProblems(record, "", conformance);
    socialProblems(record.get("social_profiles"), "/social_profiles", conformance);
    categoryProblems(record.get("categories"), "/categories", conformance);
    mediaProblems(record.get("media"), conformance);
    JsonNode locations = record.get("locations");
    if (locations != null && locations.isArray()) {
      for (int j = 0; j < locations.size(); j++) locationProblems(locations.get(j), "/locations/" + j, conformance);
      Set<String> ids = new HashSet<>();
      for (int j = 0; j < locations.size(); j++) {
        String id = text(locations.get(j), "location_id");
        if (id == null) continue;
        if (!ids.add(id)) conformance.add(new Problem("/locations/" + j + "/location_id", "location_id \"" + id + "\" is not unique."));
      }
    }
    listingProblems(record, "", conformance);
    taxProblems(record.get("tax_registrations"), conformance);
    String key = text(record, "business_key");
    if (key != null) {
      BusinessKey.Parsed parsed = BusinessKey.parse(key);
      if (!parsed.ok()) {
        businessKey.add(new Problem("/business_key", parsed.message()));
      } else {
        if (countryCode != null && !parsed.key().country().equals(countryCode.toLowerCase(Locale.ROOT))) {
          businessKey.add(new Problem("/business_key", "business_key's country does not match country."));
        }
        if (!parsed.key().number().equals(jsString(record.get("registration_number")).toUpperCase(Locale.ROOT))) {
          businessKey.add(new Problem("/business_key", "business_key's registration number does not match registration_number."));
        }
      }
    }
  }

  private static void locationProblems(JsonNode loc, String where, List<Problem> out) {
    if (loc == null || !loc.isObject()) return;
    for (String key : List.of("street", "city", "postal_code")) {
      if (loc.has(key)) out.add(new Problem(where + "/" + key, key + " is not a location member; use address."));
    }
    JsonNode addr = loc.get("address");
    JsonNode addrCountry = addr == null ? null : addr.get("country");
    if (addrCountry != null && addrCountry.isObject()) {
      String code = text(addrCountry, "code");
      if (code != null) {
        String problem = countryCodeProblem(code);
        if (problem != null) out.add(new Problem(where + "/address/country/code", problem));
      }
    }
    JsonNode region = addr == null ? null : addr.get("region");
    String regionCode = region == null ? null : text(region, "code");
    String addressCountry = addrCountry == null ? null : text(addrCountry, "code");
    if (regionCode != null && addressCountry != null) {
      String problem = BusinessKey.regionCodeProblem(regionCode, addressCountry);
      if (problem != null) out.add(new Problem(where + "/address/region/code", problem));
    }
    JsonNode geo = loc.get("geo");
    if (geo != null && !geo.isNull() && !isFalsy(geo)) {
      JsonNode lines = addr == null ? null : addr.get("street_lines");
      boolean street = lines != null && lines.isArray() && lines.size() > 0;
      if (!street) out.add(new Problem(where + "/geo", "geo requires address.street_lines."));
      JsonNode lat = geo.get("latitude");
      JsonNode lon = geo.get("longitude");
      if (lat == null || !lat.isNumber() || lat.doubleValue() < -90 || lat.doubleValue() > 90
          || lon == null || !lon.isNumber() || lon.doubleValue() < -180 || lon.doubleValue() > 180) {
        out.add(new Problem(where + "/geo", "geo coordinates out of valid WGS 84 range."));
      }
    }
    httpsProblem(loc.get("website"), where + "/website", "website", out);
    socialProblems(loc.get("social_profiles"), where + "/social_profiles", out);
    categoryProblems(loc.get("categories"), where + "/categories", out);
    JsonNode listings = loc.get("external_listings");
    if (listings != null && listings.isArray()) {
      for (int j = 0; j < listings.size(); j++) {
        httpsProblem(listings.get(j).get("public_url"), where + "/external_listings/" + j + "/public_url", "public_url", out);
      }
    }
    JsonNode hours = loc.get("opening_hours");
    if (hours != null && (hours.isObject() || hours.isArray())) openingHourProblems(hours, where + "/opening_hours", out);
    listingProblems(loc, where, out);
    JsonNode areas = loc.get("service_areas");
    if (areas != null && areas.isArray()) {
      for (int j = 0; j < areas.size(); j++) {
        JsonNode area = areas.get(j);
        String code = text(area, "code");
        if (code != null) {
          String problem = placeCodeProblem(code);
          if (problem != null) out.add(new Problem(where + "/service_areas/" + j + "/code", problem));
        } else if (text(area, "country") != null) {
          String problem = countryCodeProblem(text(area, "country"));
          if (problem != null) out.add(new Problem(where + "/service_areas/" + j + "/country", problem));
        }
      }
    }
  }

  private static void openingHourProblems(JsonNode hours, String where, List<Problem> out) {
    String zone = text(hours, "time_zone");
    if (!TIME_ZONES.isEmpty() && zone != null && !TIME_ZONES.contains(zone)) {
      out.add(new Problem(where + "/time_zone", "\"" + zone + "\" is not an IANA time zone."));
    }
    List<int[]> weeklySpans = new ArrayList<>();
    Set<String> seenDays = new HashSet<>();
    boolean overlapped = false;
    JsonNode weekly = hours.get("weekly");
    for (JsonNode entry : weekly != null && weekly.isArray() ? weekly : List.<JsonNode>of()) {
      String day = jsString(entry.get("day"));
      if (!seenDays.add(day)) {
        out.add(new Problem(where + "/weekly", "weekly lists " + day + " more than once."));
        continue;
      }
      JsonNode periods = arrayOrEmpty(entry.get("periods"));
      if (!inOrder(periods)) out.add(new Problem(where + "/weekly", day + ": periods are not in order of opens."));
      int dayIndex = DAYS.indexOf(day);
      if (dayIndex < 0) continue;
      List<int[]> spans = new ArrayList<>();
      String spanProblem = periodSpans(periods, dayIndex, spans);
      if (spanProblem != null) {
        out.add(new Problem(where + "/weekly", day + ": " + spanProblem));
        continue;
      }
      if (overlap(spans, null)) {
        overlapped = true;
        out.add(new Problem(where + "/weekly", day + ": periods overlap."));
      }
      weeklySpans.addAll(spans);
    }
    if (!overlapped && overlap(weeklySpans, 7 * 1440)) {
      out.add(new Problem(where + "/weekly", "an overnight period overlaps the next day's hours."));
    }
    Set<String> seenDates = new HashSet<>();
    JsonNode exceptions = hours.get("exceptions");
    for (JsonNode entry : exceptions != null && exceptions.isArray() ? exceptions : List.<JsonNode>of()) {
      String date = jsString(entry.get("date"));
      if (!seenDates.add(date)) {
        out.add(new Problem(where + "/exceptions", "exceptions lists " + date + " more than once."));
        continue;
      }
      JsonNode periods = arrayOrEmpty(entry.get("periods"));
      if (!inOrder(periods)) out.add(new Problem(where + "/exceptions", date + ": periods are not in order of opens."));
      List<int[]> spans = new ArrayList<>();
      String spanProblem = periodSpans(periods, null, spans);
      if (spanProblem != null) out.add(new Problem(where + "/exceptions", date + ": " + spanProblem));
      else if (overlap(spans, null)) out.add(new Problem(where + "/exceptions", date + ": periods overlap."));
    }
  }

  private static boolean inOrder(JsonNode periods) {
    String previous = null;
    for (JsonNode period : periods) {
      String opens = jsString(period.get("opens"));
      if (previous != null && opens.compareTo(previous) < 0) return false;
      previous = opens;
    }
    return true;
  }

  private static String periodSpans(JsonNode periods, Integer dayIndex, List<int[]> spans) {
    int base = dayIndex == null ? 0 : dayIndex * 1440;
    for (JsonNode period : periods) {
      String opensText = jsString(period.get("opens"));
      String closesText = jsString(period.get("closes"));
      Integer opens = minutes(opensText);
      Integer closes = minutes(closesText);
      if (opens == null || closes == null) return "a period is not a HH:MM time.";
      if (closes.intValue() == opens.intValue()) return "period " + opensText + "-" + closesText + " opens and closes at the same time.";
      int end = closes < opens ? closes + 1440 : closes;
      spans.add(new int[] {base + opens, base + end});
    }
    return null;
  }

  /** SPEC section 4.7.6.4. {@code wrap} copies spans that start on Monday a week on, so a Sunday overnight can meet them. */
  private static boolean overlap(List<int[]> spans, Integer wrap) {
    List<int[]> ordered = new ArrayList<>(spans);
    if (wrap != null) {
      for (int[] span : spans) if (span[0] < 1440) ordered.add(new int[] {span[0] + wrap, span[1] + wrap});
    }
    ordered.sort((a, b) -> Integer.compare(a[0], b[0]));
    for (int j = 0; j + 1 < ordered.size(); j++) {
      if (ordered.get(j + 1)[0] < ordered.get(j)[1]) return true;
    }
    return false;
  }

  private static Integer minutes(String value) {
    Matcher m = HH_MM.matcher(value);
    if (!m.matches()) return null;
    return Integer.parseInt(m.group(1)) * 60 + Integer.parseInt(m.group(2));
  }

  private static void listingProblems(JsonNode holder, String where, List<Problem> out) {
    JsonNode summaries = holder.get("review_summaries");
    if (summaries == null || !summaries.isArray()) return;
    Set<String> platforms = new HashSet<>();
    for (int j = 0; j < summaries.size(); j++) {
      JsonNode item = summaries.get(j);
      String base = where + "/review_summaries/" + j;
      JsonNode rating = item.get("rating");
      JsonNode scale = item.get("rating_scale");
      if (rating != null && rating.isNumber() && scale != null && scale.isNumber() && rating.doubleValue() > scale.doubleValue()) {
        out.add(new Problem(base + "/rating", "rating " + Jcs.number(rating.doubleValue()) + " exceeds rating_scale "
            + Jcs.number(scale.doubleValue()) + "."));
      }
      String platform = text(item, "platform");
      if (platform != null && !platforms.add(platform)) {
        out.add(new Problem(base + "/platform", "more than one summary for " + platform + "."));
      }
      httpsProblem(item.get("source_url"), base + "/source_url", "source_url", out);
    }
  }

  private static void forbiddenKeyProblems(JsonNode value, String path, List<Problem> out) {
    if (value == null) return;
    if (value.isArray()) {
      for (int j = 0; j < value.size(); j++) forbiddenKeyProblems(value.get(j), path + "/" + j, out);
      return;
    }
    if (!value.isObject()) return;
    for (Map.Entry<String, JsonNode> entry : value.properties()) {
      String here = path + "/" + entry.getKey();
      if (FORBIDDEN_KEYS.contains(entry.getKey())) out.add(new Problem(here, entry.getKey() + " is not allowed."));
      forbiddenKeyProblems(entry.getValue(), here, out);
    }
  }

  private static void httpsProblem(JsonNode value, String path, String label, List<Problem> out) {
    if (value != null && value.isTextual() && !Hosts.isSafeHttpsUrl(value.textValue())) {
      out.add(new Problem(path, label + " must be an https URL with a public DNS host name."));
    }
  }

  private static void socialProblems(JsonNode profiles, String where, List<Problem> out) {
    if (profiles == null || !profiles.isObject()) return;
    for (Map.Entry<String, JsonNode> entry : profiles.properties()) {
      httpsProblem(entry.getValue(), where + "/" + entry.getKey(), entry.getKey(), out);
    }
  }

  private static void categoryProblems(JsonNode categories, String where, List<Problem> out) {
    if (categories == null || !(categories.isObject() || categories.isArray())) return;
    taxonomyProblem(categories.get("primary"), where + "/primary/taxonomy", out);
    JsonNode additional = categories.get("additional");
    if (additional != null && additional.isArray()) {
      for (int j = 0; j < additional.size(); j++) taxonomyProblem(additional.get(j), where + "/additional/" + j + "/taxonomy", out);
    }
  }

  private static void taxonomyProblem(JsonNode category, String path, List<Problem> out) {
    if (category == null || !(category.isObject() || category.isArray())) return;
    String taxonomy = text(category, "taxonomy");
    if (taxonomy != null && HTTP_PREFIX.matcher(taxonomy).find()) httpsProblem(category.get("taxonomy"), path, "taxonomy", out);
  }

  private static void mediaProblems(JsonNode items, List<Problem> out) {
    if (items == null || !items.isArray()) return;
    Set<String> ids = new HashSet<>();
    Set<Double> positions = new HashSet<>();
    for (int j = 0; j < items.size(); j++) {
      JsonNode item = items.get(j);
      String id = text(item, "id");
      if (id != null && !ids.add(id)) out.add(new Problem("/media/" + j + "/id", "media id \"" + id + "\" is not unique."));
      JsonNode position = item.get("position");
      if (position != null && position.isNumber() && !positions.add(position.doubleValue())) {
        out.add(new Problem("/media/" + j + "/position", "media position " + Jcs.number(position.doubleValue()) + " is not unique."));
      }
      httpsProblem(item.get("url"), "/media/" + j + "/url", "url", out);
      JsonNode decorative = item.get("decorative");
      String alt = text(item, "alt_text");
      if (!"video".equals(text(item, "kind")) && !(decorative != null && decorative.isBoolean() && decorative.booleanValue())
          && (alt == null || Text.jsTrim(alt).isEmpty())) {
        out.add(new Problem("/media/" + j + "/alt_text", "an image needs alt_text unless decorative is true."));
      }
    }
  }

  private static void taxProblems(JsonNode items, List<Problem> out) {
    if (items == null || !items.isArray()) return;
    Set<String> seen = new HashSet<>();
    for (int j = 0; j < items.size(); j++) {
      JsonNode item = items.get(j);
      String jurisdiction = text(item, "jurisdiction");
      if (jurisdiction != null) {
        String problem = placeCodeProblem(jurisdiction);
        if (problem != null) out.add(new Problem("/tax_registrations/" + j + "/jurisdiction", problem));
      }
      String id = jsString(item.get("jurisdiction")) + "|" + jsString(item.get("scheme")) + "|" + jsString(item.get("number"));
      if (!seen.add(id)) out.add(new Problem("/tax_registrations/" + j, "tax registration jurisdiction, scheme and number are not unique."));
      String expires = text(item, "verification_expires_at");
      String verified = text(item, "verified_at");
      if (expires != null && verified != null) {
        Long e = instant(expires);
        Long v = instant(verified);
        if (e == null || v == null || e <= v) {
          out.add(new Problem("/tax_registrations/" + j + "/verification_expires_at", "verification_expires_at must be later than verified_at."));
        }
      }
    }
  }

  private static Long instant(String value) {
    try {
      return OffsetDateTime.parse(value).toInstant().toEpochMilli();
    } catch (DateTimeParseException e) {
      return null;
    }
  }

  private static String countryCodeProblem(String code) {
    if (!Iso3166.isAssignedCountry(code)) return "\"" + code + "\" is not an assigned ISO 3166-1 alpha-2 code.";
    return BusinessKey.countrySupportProblem(code);
  }

  private static String placeCodeProblem(String code) {
    int dash = code.indexOf('-');
    String country = dash < 0 ? code : code.substring(0, dash);
    String assigned = countryCodeProblem(country);
    if (assigned != null) return assigned;
    return dash >= 0 ? BusinessKey.regionCodeProblem(code, country) : null;
  }

  // ------------------------------------------------------------------------------------------

  private static String text(JsonNode node, String field) {
    if (node == null || !node.isObject()) return null;
    JsonNode value = node.get(field);
    return value != null && value.isTextual() ? value.textValue() : null;
  }

  private static String nestedCode(JsonNode value) {
    return value != null && value.isObject() ? text(value, "code") : null;
  }

  /** {@code String(value)} for the values the checks compare. */
  private static String jsString(JsonNode value) {
    if (value == null || value.isMissingNode()) return "undefined";
    if (value.isTextual()) return value.textValue();
    if (value.isNull()) return "null";
    if (value.isNumber()) return Jcs.number(value.doubleValue());
    if (value.isBoolean()) return value.booleanValue() ? "true" : "false";
    if (value.isArray()) {
      List<String> parts = new ArrayList<>();
      for (JsonNode item : value) parts.add(item.isNull() ? "" : jsString(item));
      return String.join(",", parts);
    }
    return "[object Object]";
  }

  private static boolean isFalsy(JsonNode value) {
    return (value.isBoolean() && !value.booleanValue()) || (value.isNumber() && value.doubleValue() == 0)
        || (value.isTextual() && value.textValue().isEmpty());
  }

  private static JsonNode arrayOrEmpty(JsonNode value) {
    return value != null && value.isArray() ? value : StrictJson.mapper().createArrayNode();
  }

  private static Iterable<JsonNode> iterable(JsonNode value) {
    return value != null && value.isArray() ? value : List.of();
  }

  private static String clip(String s, int n) {
    return s.length() > n ? s.substring(0, n) : s;
  }
}
