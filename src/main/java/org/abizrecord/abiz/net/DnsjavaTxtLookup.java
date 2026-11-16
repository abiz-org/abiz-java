package org.abizrecord.abiz.net;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.abizrecord.abiz.TxtLookup;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Section;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;
import org.xbill.DNS.WireParseException;

/**
 * DNS through dnsjava: the TXT port and the fetch guard's A/AAAA lookup. Each query is sent
 * directly (no cache, no search list), so NXDOMAIN, NODATA, SERVFAIL, REFUSED and a timeout stay
 * distinct. By default it asks the system's configured DNS servers ({@code /etc/resolv.conf} or the
 * platform equivalent, as dnsjava reads it) with a 2.5-second limit per query.
 */
public final class DnsjavaTxtLookup implements TxtLookup {
  /** The time limit for one DNS query. */
  public static final Duration TIMEOUT = Duration.ofMillis(2_500);

  private final Resolver resolver;
  private final Duration timeout;

  /** Queries the system's DNS servers. */
  public DnsjavaTxtLookup() {
    this(defaultResolver(), TIMEOUT);
  }

  /**
   * Queries through the given dnsjava resolver, for example a {@code SimpleResolver} for one
   * server or a {@code DohResolver}.
   *
   * @param resolver the resolver
   * @param timeout the time limit for one query
   */
  public DnsjavaTxtLookup(Resolver resolver, Duration timeout) {
    this.resolver = resolver;
    this.timeout = timeout;
    this.resolver.setTimeout(timeout);
    if (resolver instanceof ExtendedResolver) {
      for (Resolver each : ((ExtendedResolver) resolver).getResolvers()) each.setTimeout(timeout);
    }
  }

  private static Resolver defaultResolver() {
    ExtendedResolver resolver = new ExtendedResolver();
    resolver.setRetries(1);
    return resolver;
  }

  @Override
  public TxtLookup.Result lookup(String name) {
    Message response;
    try {
      response = query(name, Type.TXT);
    } catch (Failure failure) {
      return new TxtLookup.Failure(failure.reason);
    }
    switch (response.getRcode()) {
      case Rcode.NOERROR: {
        List<String> values = new ArrayList<>();
        for (Record record : response.getSection(Section.ANSWER)) {
          if (!(record instanceof TXTRecord)) continue;
          ByteArrayOutputStream joined = new ByteArrayOutputStream();
          for (byte[] part : ((TXTRecord) record).getStringsAsByteArrays()) joined.write(part, 0, part.length);
          values.add(new String(joined.toByteArray(), StandardCharsets.UTF_8));
        }
        return values.isEmpty() ? new TxtLookup.NoData() : new TxtLookup.Answer(values);
      }
      case Rcode.NXDOMAIN:
        return new TxtLookup.NxDomain();
      case Rcode.SERVFAIL:
        return new TxtLookup.Failure(TxtLookup.Reason.SERVFAIL);
      case Rcode.REFUSED:
        return new TxtLookup.Failure(TxtLookup.Reason.REFUSED);
      default:
        return new TxtLookup.Failure(TxtLookup.Reason.MALFORMED);
    }
  }

  /**
   * The fetch guard's address lookup through the same resolver: A and AAAA, both of which must
   * complete (NOERROR or NXDOMAIN) for the result to count.
   *
   * @return the address resolver
   */
  public AddressResolver addressResolver() {
    return host -> {
      List<byte[]> out = new ArrayList<>();
      for (int type : new int[] {Type.A, Type.AAAA}) {
        Message response;
        try {
          response = query(host, type);
        } catch (Failure failure) {
          return new AddressResolver.Failed();
        }
        int rcode = response.getRcode();
        if (rcode != Rcode.NOERROR && rcode != Rcode.NXDOMAIN) return new AddressResolver.Failed();
        for (Record record : response.getSection(Section.ANSWER)) {
          // Raw rdata, so an IPv4-mapped AAAA answer stays 16 bytes (InetAddress would turn it into IPv4).
          if (record instanceof ARecord || record instanceof AAAARecord) out.add(record.rdataToWireCanonical());
        }
      }
      return new AddressResolver.Found(out);
    };
  }

  private Message query(String name, int type) throws Failure {
    Name owner;
    try {
      owner = Name.fromString(name, Name.root);
    } catch (TextParseException e) {
      throw new Failure(TxtLookup.Reason.MALFORMED);
    }
    Message query = Message.newQuery(Record.newRecord(owner, type, DClass.IN));
    CompletableFuture<Message> future = resolver.sendAsync(query).toCompletableFuture();
    try {
      // dnsjava enforces the timeout itself; this bound is a backstop.
      return future.get(timeout.toMillis() + 500, TimeUnit.MILLISECONDS);
    } catch (TimeoutException e) {
      future.cancel(true);
      throw new Failure(TxtLookup.Reason.TIMEOUT);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new Failure(TxtLookup.Reason.NETWORK);
    } catch (ExecutionException e) {
      Throwable cause = e.getCause();
      if (cause instanceof SocketTimeoutException || cause instanceof TimeoutException) throw new Failure(TxtLookup.Reason.TIMEOUT);
      if (cause instanceof WireParseException) throw new Failure(TxtLookup.Reason.MALFORMED);
      if (cause instanceof IOException) throw new Failure(TxtLookup.Reason.NETWORK);
      throw new Failure(TxtLookup.Reason.NETWORK);
    } catch (RuntimeException e) {
      throw new Failure(TxtLookup.Reason.NETWORK);
    }
  }

  private static final class Failure extends Exception {
    private static final long serialVersionUID = 1L;
    private final transient TxtLookup.Reason reason;

    Failure(TxtLookup.Reason reason) {
      super(null, null, false, false);
      this.reason = reason;
    }
  }
}
