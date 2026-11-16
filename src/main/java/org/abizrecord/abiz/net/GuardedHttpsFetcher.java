package org.abizrecord.abiz.net;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.abizrecord.abiz.Abiz;
import org.abizrecord.abiz.Addresses;
import org.abizrecord.abiz.Hosts;
import org.abizrecord.abiz.RecordFetcher;

/**
 * The fetch guard (SPEC section 9) over a raw TLS socket.
 *
 * <p>Why not {@code java.net.http.HttpClient} or {@code HttpsURLConnection}: both look the host
 * name up again when they connect, so the address checked by the guard and the address connected
 * to could differ (DNS rebinding). This class resolves the name once, refuses unless every address
 * is public unicast ({@link Addresses}), opens a TCP connection to one of those checked addresses
 * itself, and only then layers TLS over that socket with the server name set for SNI and the
 * certificate checked against the name ({@code HTTPS} endpoint identification). It then speaks a
 * single HTTP/1.1 GET.
 *
 * <p>Limits: port 443 only, no redirects (a 3xx is returned as is), 5 seconds over the whole
 * exchange, 64 KiB of decoded body, {@code Accept: application/json}. Proxies are not used: a proxy
 * would resolve the name itself, which is what the guard exists to prevent. A caller that must use
 * a proxy supplies its own {@link RecordFetcher}.
 */
public final class GuardedHttpsFetcher implements RecordFetcher {
  /** The time limit over the whole exchange. */
  public static final int TIMEOUT_MILLIS = 5_000;
  /** The largest body read, after decoding. */
  public static final int MAX_BODY_BYTES = 65_536;
  private static final int MAX_HEADER_BYTES = 32_768;
  private static final Pattern IPV4ISH = Pattern.compile("^[0-9.]+\\z");
  private static final Pattern TARGET = Pattern.compile("^/[\\x21-\\x7e]*\\z");

  private final AddressResolver addresses;
  private final SSLSocketFactory tls;
  private final int timeoutMillis;

  /**
   * A fetcher using the JDK's default trust store.
   *
   * @param addresses the A/AAAA lookup, for example {@link DnsjavaTxtLookup#addressResolver()}
   */
  public GuardedHttpsFetcher(AddressResolver addresses) {
    this(addresses, defaultFactory(), TIMEOUT_MILLIS);
  }

  /**
   * A fetcher with its own TLS settings and time limit.
   *
   * @param addresses the A/AAAA lookup
   * @param tls the TLS socket factory (its trust store decides which certificates are accepted)
   * @param timeoutMillis the time limit over the whole exchange
   */
  public GuardedHttpsFetcher(AddressResolver addresses, SSLSocketFactory tls, int timeoutMillis) {
    this.addresses = addresses;
    this.tls = tls;
    this.timeoutMillis = timeoutMillis;
  }

  private static SSLSocketFactory defaultFactory() {
    try {
      return SSLContext.getDefault().getSocketFactory();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("no default TLS context", e);
    }
  }

  @Override
  public Outcome fetch(String url) {
    if (!url.startsWith("https://")) return new Blocked("Only https URLs are fetched.");
    String rest = url.substring("https://".length());
    int end = rest.length();
    for (int i = 0; i < rest.length(); i++) {
      char c = rest.charAt(i);
      if (c == '/' || c == '?' || c == '#') {
        end = i;
        break;
      }
    }
    String host = rest.substring(0, end).toLowerCase(Locale.ROOT);
    String target = rest.substring(end);
    int hash = target.indexOf('#');
    if (hash >= 0) target = target.substring(0, hash);
    if (target.isEmpty()) target = "/";
    if (target.startsWith("?")) target = "/" + target;
    if (host.contains("@") || host.contains(":") || host.contains("[")) {
      return new Blocked("Only https on the default port, without credentials, is fetched.");
    }
    if (!TARGET.matcher(target).matches()) return new Blocked("The record address is not a valid URL.");
    if (IPV4ISH.matcher(host).matches() || !Hosts.isSafeHost(host) || Hosts.isNonPublicHost(host)) {
      return new Blocked("The record host is a private or special-use name.");
    }
    if (host.endsWith(".")) host = host.substring(0, host.length() - 1);

    AddressResolver.Result lookup;
    try {
      lookup = addresses.resolve(host);
    } catch (RuntimeException e) {
      return new DnsError();
    }
    if (!(lookup instanceof AddressResolver.Found)) return new DnsError();
    List<byte[]> found = ((AddressResolver.Found) lookup).addresses();
    if (found.isEmpty()) return new NoAddress();
    for (byte[] address : found) {
      if (!Addresses.isPublic(address)) {
        return new Blocked("The record host resolves to a private, reserved or special-purpose address.");
      }
    }
    return exchange(host, target, found);
  }

  private Outcome exchange(String host, String target, List<byte[]> checked) {
    long deadline = System.nanoTime() + timeoutMillis * 1_000_000L;
    Socket socket = null;
    for (byte[] raw : checked) {
      int remaining = remaining(deadline);
      if (remaining <= 0) return new Timeout();
      Socket attempt = new Socket(java.net.Proxy.NO_PROXY);
      try {
        // The checked address itself, never the name: no second lookup can change where we connect.
        InetAddress address = raw.length == 16 ? java.net.Inet6Address.getByAddress(null, raw, -1) : InetAddress.getByAddress(raw);
        attempt.connect(new InetSocketAddress(address, 443), remaining);
        socket = attempt;
        break;
      } catch (IOException e) {
        closeQuietly(attempt);
      }
    }
    if (socket == null) return remaining(deadline) <= 0 ? new Timeout() : new Network();
    try (Socket plain = socket;
        SSLSocket ssl = (SSLSocket) tls.createSocket(plain, host, 443, true)) {
      SSLParameters params = ssl.getSSLParameters();
      params.setEndpointIdentificationAlgorithm("HTTPS");
      params.setServerNames(List.of(new SNIHostName(host)));
      ssl.setSSLParameters(params);
      ssl.setSoTimeout(Math.max(1, remaining(deadline)));
      ssl.startHandshake();
      OutputStream out = ssl.getOutputStream();
      String request = "GET " + target + " HTTP/1.1\r\n"
          + "Host: " + host + "\r\n"
          + "Accept: application/json\r\n"
          + "Accept-Encoding: identity\r\n"
          + "User-Agent: " + Abiz.USER_AGENT + "\r\n"
          + "Connection: close\r\n\r\n";
      out.write(request.getBytes(StandardCharsets.US_ASCII));
      out.flush();
      return readResponse(new DeadlineInputStream(ssl, deadline));
    } catch (SocketTimeoutException e) {
      return new Timeout();
    } catch (IOException | RuntimeException e) {
      return remaining(deadline) <= 0 ? new Timeout() : new Network();
    }
  }

  private static Outcome readResponse(DeadlineInputStream in) throws IOException {
    int status;
    String contentType = null;
    String transferEncoding = null;
    String contentEncoding = null;
    String contentLength = null;
    int headerBytes = 0;
    while (true) {
      String statusLine = readLine(in);
      headerBytes += statusLine.length();
      String[] parts = statusLine.split(" ", 3);
      if (parts.length < 2 || !parts[0].startsWith("HTTP/1.") || !parts[1].matches("[0-9]{3}")) {
        throw new IOException("not an HTTP/1.x response");
      }
      status = Integer.parseInt(parts[1]);
      contentType = null;
      transferEncoding = null;
      contentEncoding = null;
      contentLength = null;
      while (true) {
        String line = readLine(in);
        headerBytes += line.length() + 2;
        if (headerBytes > MAX_HEADER_BYTES) throw new IOException("response headers too large");
        if (line.isEmpty()) break;
        int colon = line.indexOf(':');
        if (colon <= 0) continue;
        String name = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
        String value = line.substring(colon + 1).trim();
        if (name.equals("content-type") && contentType == null) contentType = value;
        else if (name.equals("transfer-encoding")) transferEncoding = value.toLowerCase(Locale.ROOT);
        else if (name.equals("content-encoding")) contentEncoding = value.toLowerCase(Locale.ROOT);
        else if (name.equals("content-length") && contentLength == null) contentLength = value;
      }
      if (status >= 100 && status < 200 && status != 101) continue; // interim response
      break;
    }
    if (status != 200) return new Response(status, contentType, "");

    InputStream body;
    if (transferEncoding != null && transferEncoding.endsWith("chunked")) {
      body = new ChunkedInputStream(in);
    } else if (contentLength != null) {
      if (!contentLength.matches("[0-9]{1,18}")) throw new IOException("bad Content-Length");
      long length = Long.parseLong(contentLength);
      if (length > MAX_BODY_BYTES && (contentEncoding == null || contentEncoding.equals("identity"))) {
        return new Response(200, contentType, null);
      }
      body = new LimitedInputStream(in, length);
    } else {
      body = in;
    }
    if (contentEncoding != null && !contentEncoding.isEmpty() && !contentEncoding.equals("identity")) {
      if (contentEncoding.equals("gzip") || contentEncoding.equals("x-gzip")) body = new GZIPInputStream(body);
      else if (contentEncoding.equals("deflate")) body = new InflaterInputStream(body);
      else throw new IOException("unsupported Content-Encoding " + contentEncoding);
    }
    byte[] bytes = readCapped(body, MAX_BODY_BYTES);
    if (bytes == null) return new Response(200, contentType, null);
    String text = new String(bytes, StandardCharsets.UTF_8);
    if (text.startsWith("﻿")) text = text.substring(1); // as the WHATWG UTF-8 decoder does
    return new Response(200, contentType, text);
  }

  private static byte[] readCapped(InputStream in, int max) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] buffer = new byte[8192];
    int total = 0;
    int n;
    while ((n = in.read(buffer)) != -1) {
      total += n;
      if (total > max) return null;
      out.write(buffer, 0, n);
    }
    return out.toByteArray();
  }

  private static String readLine(InputStream in) throws IOException {
    StringBuilder line = new StringBuilder();
    while (true) {
      int b = in.read();
      if (b == -1) throw new IOException("connection closed in the headers");
      if (b == '\n') break;
      if (line.length() > MAX_HEADER_BYTES) throw new IOException("header line too long");
      line.append((char) b);
    }
    int len = line.length();
    if (len > 0 && line.charAt(len - 1) == '\r') line.setLength(len - 1);
    return line.toString();
  }

  private static int remaining(long deadline) {
    long left = (deadline - System.nanoTime()) / 1_000_000L;
    return (int) Math.max(0, Math.min(Integer.MAX_VALUE, left));
  }

  private static void closeQuietly(Socket socket) {
    try {
      socket.close();
    } catch (IOException ignored) {
      // nothing to do
    }
  }

  /** Reads from the socket, never past the deadline. */
  private static final class DeadlineInputStream extends InputStream {
    private final SSLSocket socket;
    private final InputStream in;
    private final long deadline;

    DeadlineInputStream(SSLSocket socket, long deadline) throws IOException {
      this.socket = socket;
      this.in = socket.getInputStream();
      this.deadline = deadline;
    }

    private void arm() throws IOException {
      int left = remaining(deadline);
      if (left <= 0) throw new SocketTimeoutException("deadline passed");
      socket.setSoTimeout(left);
    }

    @Override
    public int read() throws IOException {
      arm();
      return in.read();
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      arm();
      return in.read(b, off, len);
    }
  }

  /** Exactly {@code length} bytes, then end of stream; a short body is an error. */
  private static final class LimitedInputStream extends InputStream {
    private final InputStream in;
    private long left;

    LimitedInputStream(InputStream in, long length) {
      this.in = in;
      this.left = length;
    }

    @Override
    public int read() throws IOException {
      byte[] one = new byte[1];
      int n = read(one, 0, 1);
      return n == -1 ? -1 : one[0] & 0xff;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      if (left <= 0) return -1;
      int n = in.read(b, off, (int) Math.min(len, left));
      if (n == -1) throw new IOException("connection closed before Content-Length bytes");
      left -= n;
      return n;
    }
  }

  /** HTTP/1.1 chunked transfer coding; trailers are read and dropped. */
  private static final class ChunkedInputStream extends InputStream {
    private final InputStream in;
    private long chunkLeft;
    private boolean done;

    ChunkedInputStream(InputStream in) {
      this.in = in;
    }

    @Override
    public int read() throws IOException {
      byte[] one = new byte[1];
      int n = read(one, 0, 1);
      return n == -1 ? -1 : one[0] & 0xff;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      if (done) return -1;
      if (chunkLeft == 0) {
        String size = readLine(in);
        int semi = size.indexOf(';');
        if (semi >= 0) size = size.substring(0, semi);
        size = size.trim();
        if (!size.matches("[0-9A-Fa-f]{1,8}")) throw new IOException("bad chunk size");
        chunkLeft = Long.parseLong(size, 16);
        if (chunkLeft == 0) {
          while (!readLine(in).isEmpty()) {
            // trailer fields are ignored
          }
          done = true;
          return -1;
        }
      }
      int n = in.read(b, off, (int) Math.min(len, chunkLeft));
      if (n == -1) throw new IOException("connection closed in a chunk");
      chunkLeft -= n;
      if (chunkLeft == 0 && !readLine(in).isEmpty()) throw new IOException("bad chunk terminator");
      return n;
    }
  }
}
