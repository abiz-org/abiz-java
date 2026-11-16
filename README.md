# ABIZ for Java

Resolve and check [ABIZ](https://abizrecord.org) (Agentic Business Record) 1.1 records from Java.

A domain publishes an `_abiz` DNS TXT record (`v=abiz1;k=…;h=…;p=…`) that points at a signed JSON
business record served over HTTPS. This library is the consumer side: given a domain, it finds the
assertion, fetches the record, checks it, and gives the same status and error code as the hosted
resolver at `resolve.abizrecord.org`.

- Maven coordinates: `org.abizrecord:abiz:2026.1116.1`
- Java 17 or later
- Implements ABIZ 1.1 and passes every case of the shared test vectors, format 1
- Licence: Apache-2.0 (the bundled `iso3166.json` is LGPL-2.1; see [NOTICE](NOTICE))

Releases are published to Maven Central from tags; see [RELEASING.md](RELEASING.md).

## Install

```xml
<dependency>
  <groupId>org.abizrecord</groupId>
  <artifactId>abiz</artifactId>
  <version>2026.1116.1</version>
</dependency>
```

Gradle: `implementation("org.abizrecord:abiz:2026.1116.1")`.

It depends on dnsjava 3.7.0 (DNS), Jackson 2.22.4 (JSON) and networknt json-schema-validator 2.0.8
(JSON Schema 2020-12). Ed25519 is the JDK's own (`java.security`, Java 15 and later).

## Example

```java
import org.abizrecord.abiz.Abiz;
import org.abizrecord.abiz.ResolveResult;

ResolveResult result = Abiz.resolve("example.com");
if (result.resolved()) {
  System.out.println(result.record().get("business_name").asText());
} else {
  System.out.println(result.status() + " " + result.code() + ": " + result.message());
  if (result.retryable()) System.out.println("Try again later; this does not mean there is no record.");
}
```

## What is checked

1. **Input.** The domain is lower-cased, IDN is converted to A-labels and one trailing dot is
   dropped. A URL, port, credentials or IP address is `invalid_domain` (`invalid_website` for a
   website address); a special-use or private-network name is `non_public_domain`. `www.` is
   never stripped: when nothing is found at a `www.` name, a `try_apex` warning suggests the apex.
2. **DNS.** One TXT query for `_abiz.<domain>`. NXDOMAIN and NODATA mean "nothing published"; a
   timeout or network failure is `dns_timeout`, and SERVFAIL, REFUSED or an unreadable answer is
   `dns_failure`. A failure is never treated as "nothing published".
3. **The assertion** (SPEC sections 3.1 to 3.3): exactly one `v=abiz1` value, the tag-list syntax,
   `h` a host with an optional path, `k` a business key, `p` an Ed25519 public key in canonical
   standard base64.
4. **The well-known file**, `https://<domain>/.well-known/abiz.json`, only when DNS answered with
   no `v=abiz1` value.
5. **One guarded fetch** of `https://<h>?format=json`: every address the host resolves to must be
   public unicast, the connection goes to a checked address, TLS is verified against the name, no
   redirect is followed, 5 seconds, 64 KiB.
6. **The record**: I-JSON (a repeated member name is rejected), nesting depth 16 and 5,000
   members at most, the bundled JSON Schema 2020-12 with formats asserted, the semantic checks of
   the reference validator (country and region codes, URLs, opening hours, unique ids, and so on),
   `identity_host` equal to `h`, `domains` including the queried domain, the business key in
   agreement with `k`, `country` and `registration_number`, `public_key` equal to `p`, and the
   Ed25519 `signature` over the RFC 8785 (JCS) form of the record without its `signature`.

## What is not checked

- **No company register is queried.** A business name, registration number or business key in a
  record is the publisher's own claim.
- **`mcp_server_url` is never called**, and no other URL in the record is fetched.
- A resolved record means: the domain's DNS (or its well-known file) names a key, and the record
  is signed with that key and passes every check above. The business facts in it are **checked**
  for form and consistency, not **verified** as true.
- DNSSEC is not validated by this library.

## API

Package `org.abizrecord.abiz`:

| Call | Returns |
| --- | --- |
| `Abiz.resolve(domain)`, `Abiz.resolveWebsite(website)` | `ResolveResult`, on the network with the default resolver |
| `new Resolver(txtLookup, recordFetcher).resolve(domain)` / `.resolveWebsite(website)` / `.resolve(domain, website)` | `ResolveResult`, with your own DNS and HTTP |
| `Abiz.parseAssertion(value)` | `AssertionResult`: the `Assertion` (`h`, `k`, `p`, unknown tags) or an `ErrorCode` |
| `Abiz.checkRecord(recordText, domain, assertion)` | `null` when the record is accepted, else the first failing `ErrorCode` (offline) |
| `Abiz.checkRecordDetailed(recordText, domain, assertion)` | `RecordCheck`: the code, the problems found and the parsed record |
| `Abiz.verifySignature(record, p)` | `null`, `PUBLIC_KEY_MISMATCH` or `SIGNATURE_INVALID` |
| `Abiz.canonicalize(jsonText)` / `Abiz.canonicalize(jsonNode)` | RFC 8785 text |
| `Abiz.signRecord(record, seed)` | A producer helper: a copy of the record with `public_key` and `signature` set |

`ResolveResult` has `status()` (`RESOLVED`, `INVALID_INPUT`, `NOT_FOUND`, `CONFLICT`,
`INVALID_RECORD`, `UNAVAILABLE`; `wireName()` gives the resolver's spelling), `code()` (null when
resolved; `code()` on it gives the wire code such as `signature_invalid`), `message()`,
`retryable()`, `details()` (path and message, at most 25), `record()` (only when resolved, exactly
as published), `domain()`, `discovery()` (`method` `dns_txt` or `well_known`, `owner`, `dnsValue`,
`recordUrl`, `wellKnown`) and `warnings()` (`content_type`, `try_apex` with a domain).

### Your own DNS or HTTP

DNS and HTTP sit behind two small interfaces, so you can use DNS-over-HTTPS, a cache, a proxy or
fixed answers in tests:

```java
TxtLookup dns = name -> new TxtLookup.Answer(List.of("v=abiz1;h=records.example.org/acme;p=..."));
RecordFetcher http = url -> new RecordFetcher.Response(200, "application/json", "{...}");
ResolveResult result = new Resolver(dns, http).resolve("acme.example.org");
```

A `TxtLookup` returns `Answer` (each TXT record's character-strings already joined), `NxDomain`,
`NoData` or `Failure` with a reason. A `RecordFetcher` must apply the fetch guard itself (see
below) and returns `Response`, `Blocked`, `NoAddress`, `DnsError`, `Timeout` or `Network`.

### The default network adapters

- `net.DnsjavaTxtLookup` sends each query directly to the system's configured DNS servers with
  dnsjava (no cache, no search list), 2.5 seconds per query, so NXDOMAIN, NODATA, SERVFAIL,
  REFUSED and a timeout stay distinct.
- `net.GuardedHttpsFetcher` implements the fetch guard over a raw TLS socket. `HttpClient` and
  `HttpsURLConnection` look the name up again when they connect, so the address checked and the
  address used could differ (DNS rebinding). This class resolves the name once (A and AAAA through
  dnsjava), refuses unless every address is public, opens the TCP connection to a checked
  address itself, then starts TLS over that socket with SNI and certificate checking against the
  name, and sends one HTTP/1.1 GET with `Accept: application/json` and
  `User-Agent: abiz-java/2026.1116.1 (+https://abizrecord.org)`. It does not use a proxy, because a
  proxy would resolve the name itself. If you must use a proxy, supply your own `RecordFetcher`.

## Conformance

The test suite runs every case of the shared vectors in `test-vectors/` (format 1, ABIZ 1.1):
assertions 56, public keys 13, hosts 52, addresses 36, JCS 13, signing 6, records 65 and
resolution 60. The bundled schema and `iso3166.json` are checked against their pinned SHA-256:

| File | SHA-256 |
| --- | --- |
| `abiz-business-record-v1.1.schema.json` | `3658f17f00c238b8c948fdfb447b509c5d055dd778ebd335495da05c3150ff24` |
| `abiz-well-known-v1.1.schema.json` | `5fe7da6fb5b6b262281402ab9dd9b46c018bf9df766203928e4e1a334cc3d741` |
| `iso3166.json` | `0aa5112c46bc2b3efb254ea9536b3cf2977c73d48149aefcd8bc20df995e5527` |

JSON Schema formats (`email`, `hostname`, `date`, `date-time`, `uri`) are asserted with the same
definitions as the reference resolver's validator, so a record is accepted or refused the same
way. `pattern` keywords are read as ECMAScript regular expressions.

Known differences from the reference resolver, none covered by the vectors:

- IDN uses the JDK's IDNA2003 (`java.net.IDN`) with the UTS #46 deviation characters `ß` and `ς`
  kept as the WHATWG URL parser keeps them. Other rare differences between IDNA2003 and UTS #46
  (for example zero-width joiners) may give a different A-label or refuse a name the reference
  accepts.
- A repeated member name in the well-known file makes it invalid (the reference keeps the last).
- TXT bytes are decoded as UTF-8.
- Time zones are those the JDK knows (`ZoneId.getAvailableZoneIds()`).

## Build

```bash
mvn -B verify
```

This runs the tests and builds `target/abiz-2026.1116.1.jar`, `-sources.jar` and `-javadoc.jar`.

## Licence

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). The bundled `iso3166.json` is
extracted from the Debian iso-codes data and is LGPL-2.1, not Apache-2.0.

Homepage: https://abizrecord.org. Source: https://github.com/abiz-org/abiz-java. Maintained by the
ABIZ contributors.
