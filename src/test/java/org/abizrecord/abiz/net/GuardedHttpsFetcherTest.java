package org.abizrecord.abiz.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import java.util.ArrayList;
import java.util.List;
import org.abizrecord.abiz.RecordFetcher;
import org.junit.jupiter.api.Test;

/** The fetch guard refuses before connecting. Every case here stops before any network I/O. */
class GuardedHttpsFetcherTest {

  /** Records the names looked up and answers from a fixed list. */
  static final class StubResolver implements AddressResolver {
    final List<String> asked = new ArrayList<>();
    final Result answer;

    StubResolver(Result answer) {
      this.answer = answer;
    }

    @Override
    public Result resolve(String host) {
      asked.add(host);
      return answer;
    }
  }

  private static byte[] v4(int a, int b, int c, int d) {
    return new byte[] {(byte) a, (byte) b, (byte) c, (byte) d};
  }

  private static byte[] v6(int... groups) {
    byte[] out = new byte[16];
    for (int i = 0; i < 8; i++) {
      out[2 * i] = (byte) (groups[i] >> 8);
      out[2 * i + 1] = (byte) groups[i];
    }
    return out;
  }

  private static RecordFetcher.Outcome fetchWith(byte[]... addresses) {
    StubResolver resolver = new StubResolver(new AddressResolver.Found(List.of(addresses)));
    RecordFetcher.Outcome outcome = new GuardedHttpsFetcher(resolver).fetch("https://records.example.org/acme?format=json");
    assertEquals(List.of("records.example.org"), resolver.asked);
    return outcome;
  }

  @Test
  void refusesLoopback() {
    assertInstanceOf(RecordFetcher.Blocked.class, fetchWith(v4(127, 0, 0, 1)));
  }

  @Test
  void refusesPrivateAndMetadataAddresses() {
    assertInstanceOf(RecordFetcher.Blocked.class, fetchWith(v4(10, 0, 0, 5)));
    assertInstanceOf(RecordFetcher.Blocked.class, fetchWith(v4(169, 254, 169, 254)));
    assertInstanceOf(RecordFetcher.Blocked.class, fetchWith(v4(192, 168, 1, 1)));
    assertInstanceOf(RecordFetcher.Blocked.class, fetchWith(v6(0xfd12, 0x3456, 0, 0, 0, 0, 0, 1)));
  }

  @Test
  void refusesWhenAnyAddressIsPrivate() {
    assertInstanceOf(RecordFetcher.Blocked.class, fetchWith(v4(8, 8, 8, 8), v4(10, 1, 2, 3)));
  }

  @Test
  void refusesIpv4MappedIpv6EvenForAPublicIpv4() {
    assertInstanceOf(RecordFetcher.Blocked.class, fetchWith(v6(0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808)));
  }

  @Test
  void noAddressAndLookupFailureAreDistinct() {
    assertInstanceOf(RecordFetcher.NoAddress.class, fetchWith());
    StubResolver failing = new StubResolver(new AddressResolver.Failed());
    assertInstanceOf(RecordFetcher.DnsError.class, new GuardedHttpsFetcher(failing).fetch("https://records.example.org/"));
  }

  @Test
  void refusesUnsafeUrlsWithoutLookingUp() {
    StubResolver resolver = new StubResolver(new AddressResolver.Found(List.of(v4(8, 8, 8, 8))));
    GuardedHttpsFetcher fetcher = new GuardedHttpsFetcher(resolver);
    for (String url : List.of("http://records.example.org/", "https://records.example.org:8443/", "https://user@records.example.org/",
        "https://192.0.2.1/", "https://[2001:db8::1]/", "https://printer.local/", "https://svc.internal/", "https://localhost/",
        "https://records.example.org/a b")) {
      assertInstanceOf(RecordFetcher.Blocked.class, fetcher.fetch(url), url);
    }
    assertEquals(List.of(), resolver.asked);
  }
}
