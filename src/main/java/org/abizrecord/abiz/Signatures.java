package org.abizrecord.abiz;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * The record's own proof (SPEC section 4.6): PureEd25519 over the UTF-8 bytes of the RFC 8785 form
 * of the record with only its top-level {@code signature} member removed. Uses the JDK's built-in
 * Ed25519 ({@code java.security}, Java 15 and later).
 */
public final class Signatures {
  private Signatures() {}

  /** Standard base64 of exactly 64 bytes. */
  private static final Pattern SIGNATURE = Pattern.compile("^[A-Za-z0-9+/]{85}[AQgw]==\\z");
  /** Standard base64 of exactly 32 bytes, canonical. */
  private static final Pattern PUBLIC_KEY = Pattern.compile("^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=\\z");
  /** DER prefix of an X.509 SubjectPublicKeyInfo for Ed25519 (RFC 8410). */
  private static final byte[] SPKI_PREFIX = hex("302a300506032b6570032100");
  /** DER prefix of a PKCS #8 PrivateKeyInfo for an Ed25519 seed (RFC 8410). */
  private static final byte[] PKCS8_PREFIX = hex("302e020100300506032b657004220420");

  /**
   * The bytes {@code signature} signs: the JCS form of the record without its top-level
   * {@code signature}, as UTF-8. A {@code signature} inside an extension is signed.
   *
   * @param record the record
   * @return the signing input
   * @throws Jcs.JcsException when the record is not I-JSON
   */
  public static byte[] signingInput(JsonNode record) {
    JsonNode rest = record;
    if (record.isObject() && record.has("signature")) {
      ObjectNode copy = ((ObjectNode) record).deepCopy();
      copy.remove("signature");
      rest = copy;
    }
    return Jcs.canonicalize(rest).getBytes(StandardCharsets.UTF_8);
  }

  /**
   * Check a record against the DNS {@code p}: {@code public_key} must equal {@code p} exactly, then
   * {@code signature} must verify.
   *
   * @param record the record
   * @param p the {@code p} tag from DNS or the well-known file (null counts as a mismatch)
   * @return null when both hold, else {@link ErrorCode#PUBLIC_KEY_MISMATCH} or
   *     {@link ErrorCode#SIGNATURE_INVALID}
   */
  public static ErrorCode verify(JsonNode record, String p) {
    Problem problem = check(record, p);
    if (problem == null) return null;
    return problem.path().equals("/public_key") ? ErrorCode.PUBLIC_KEY_MISMATCH : ErrorCode.SIGNATURE_INVALID;
  }

  /** As {@link #verify}, with where and why: the path is {@code /public_key} for a key mismatch. */
  static Problem check(JsonNode record, String p) {
    JsonNode publicKey = record.get("public_key");
    JsonNode signature = record.get("signature");
    if (publicKey == null || !publicKey.isTextual() || !PUBLIC_KEY.matcher(publicKey.textValue()).matches()
        || !publicKey.textValue().equals(p)) {
      return new Problem("/public_key", p != null
          ? "public_key must equal the DNS p= value exactly."
          : "The DNS assertion has no p= key, so the record public_key is not vouched for.");
    }
    if (signature == null || !signature.isTextual() || !SIGNATURE.matcher(signature.textValue()).matches()) {
      return new Problem("/signature", "signature must be 64 bytes of Ed25519 signature in standard base64.");
    }
    byte[] data;
    try {
      data = signingInput(record);
    } catch (Jcs.JcsException e) {
      return new Problem("$", "The record cannot be canonicalised (RFC 8785): " + e.getMessage() + ".");
    }
    boolean valid;
    try {
      Signature verifier = Signature.getInstance("Ed25519");
      verifier.initVerify(publicKey(Base64.getDecoder().decode(publicKey.textValue())));
      verifier.update(data);
      valid = verifier.verify(Base64.getDecoder().decode(signature.textValue()));
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      valid = false;
    }
    return valid ? null : new Problem("/signature",
        "signature does not verify with public_key over the RFC 8785 form of the record without signature.");
  }

  /**
   * A producer helper: the record with {@code public_key} set to the key of {@code seed} and
   * {@code signature} set to an Ed25519 signature over the rest. The input is not modified.
   *
   * @param record a JSON object
   * @param seed the 32-byte Ed25519 private key (seed)
   * @return a signed copy
   */
  public static ObjectNode sign(ObjectNode record, byte[] seed) {
    ObjectNode out = record.deepCopy();
    out.remove("signature");
    out.put("public_key", publicKeyOf(seed));
    try {
      Signature signer = Signature.getInstance("Ed25519");
      signer.initSign(privateKey(seed));
      signer.update(signingInput(out));
      out.put("signature", Base64.getEncoder().encodeToString(signer.sign()));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Ed25519 is not available in this JDK", e);
    }
    return out;
  }

  /**
   * The public key of an Ed25519 seed, as a {@code p} tag: 44 characters of standard base64.
   *
   * @param seed the 32-byte private key
   * @return the public key
   */
  public static String publicKeyOf(byte[] seed) {
    if (seed == null || seed.length != 32) throw new IllegalArgumentException("an Ed25519 seed is 32 bytes");
    try {
      // The JDK cannot derive a public key from a seed directly; a key pair generator fed the seed
      // as its "random" bytes makes exactly that key pair (RFC 8032 section 5.1.5).
      KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
      generator.initialize(NamedParameterSpec.ED25519, new FixedRandom(seed));
      KeyPair pair = generator.generateKeyPair();
      byte[] spki = pair.getPublic().getEncoded();
      return Base64.getEncoder().encodeToString(Arrays.copyOfRange(spki, spki.length - 32, spki.length));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Ed25519 is not available in this JDK", e);
    }
  }

  static PublicKey publicKey(byte[] raw) throws GeneralSecurityException {
    if (raw.length != 32) throw new GeneralSecurityException("an Ed25519 public key is 32 bytes");
    return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(concat(SPKI_PREFIX, raw)));
  }

  static PrivateKey privateKey(byte[] seed) throws GeneralSecurityException {
    if (seed.length != 32) throw new GeneralSecurityException("an Ed25519 seed is 32 bytes");
    return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(concat(PKCS8_PREFIX, seed)));
  }

  private static byte[] concat(byte[] a, byte[] b) {
    byte[] out = Arrays.copyOf(a, a.length + b.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }

  private static byte[] hex(String s) {
    byte[] out = new byte[s.length() / 2];
    for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
    return out;
  }

  /** Hands out the given bytes, once, as "random" data. */
  private static final class FixedRandom extends SecureRandom {
    private static final long serialVersionUID = 1L;
    private final byte[] bytes;
    private int used;

    FixedRandom(byte[] bytes) {
      this.bytes = bytes.clone();
    }

    @Override
    public void nextBytes(byte[] out) {
      if (used + out.length > bytes.length) throw new IllegalStateException("seed exhausted");
      System.arraycopy(bytes, used, out, 0, out.length);
      used += out.length;
    }
  }
}
