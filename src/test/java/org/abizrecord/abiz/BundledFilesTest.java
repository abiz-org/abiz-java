package org.abizrecord.abiz;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.InputStream;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** The bundled schema and country codes are byte-for-byte the pinned files. */
class BundledFilesTest {

  @ParameterizedTest
  @CsvSource({
    "abiz-business-record-v1.1.schema.json, schemas/abiz-business-record-v1.1.schema.json, 3658f17f00c238b8c948fdfb447b509c5d055dd778ebd335495da05c3150ff24",
    "abiz-well-known-v1.1.schema.json, schemas/abiz-well-known-v1.1.schema.json, 5fe7da6fb5b6b262281402ab9dd9b46c018bf9df766203928e4e1a334cc3d741",
    "iso3166.json, data/iso3166.json, 0aa5112c46bc2b3efb254ea9536b3cf2977c73d48149aefcd8bc20df995e5527",
  })
  void pinned(String resource, String vectorPath, String sha256) throws Exception {
    byte[] bundled;
    try (InputStream in = Bundled.open(resource)) {
      assertNotNull(in);
      bundled = in.readAllBytes();
    }
    assertEquals(sha256, HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bundled)));
    assertArrayEquals(Files.readAllBytes(Vectors.dir().resolve(vectorPath)), bundled);
  }

  @org.junit.jupiter.api.Test
  void constantsMatch() {
    assertEquals("3658f17f00c238b8c948fdfb447b509c5d055dd778ebd335495da05c3150ff24", Abiz.SCHEMA_SHA256);
    assertEquals("5fe7da6fb5b6b262281402ab9dd9b46c018bf9df766203928e4e1a334cc3d741", Abiz.WELL_KNOWN_SCHEMA_SHA256);
    assertEquals("0aa5112c46bc2b3efb254ea9536b3cf2977c73d48149aefcd8bc20df995e5527", Abiz.ISO3166_SHA256);
    assertEquals("abiz-java/2026.1116.1 (+https://abizrecord.org)", Abiz.USER_AGENT);
  }
}
