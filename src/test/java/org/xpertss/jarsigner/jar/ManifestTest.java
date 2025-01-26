package org.xpertss.jarsigner.jar;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 1/26/2025
 */
class ManifestTest {


   @Test
   public void testBasicDecode() throws Exception
   {
      Manifest manifest = Manifest.parse(manifestFileStream());
      assertEquals("1.0", manifest.getMain().getAttribute(Manifest.MANIFEST_VERSION));
      assertNotNull(manifest.getSection("com/manheim/simulcast/cache/Cache.class"));   // first
      assertNotNull(manifest.getSection("com/manheim/simulcast/biddisplay/DefaultFlashingStrategy$LaneModelEventHandler.class"));   // continuation
      assertNotNull(manifest.getSection("com/manheim/simulcast/biddisplay/standard/lightYellowOn.jpg")); // last
      assertFalse(manifest.isModified());
   }


   @Test
   public void testDecodeAndReEncode() throws Exception
   {
      byte[] manifestBytes = manifestFileBytes();
      Manifest manifest = Manifest.parse(new ByteArrayInputStream(manifestBytes));
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      manifest.writeTo(baos);
      assertNotEquals(0, manifestBytes.length);
      assertArrayEquals(manifestBytes, baos.toByteArray());
   }

   @Test
   public void testSectionDetails() throws Exception
   {
      Manifest manifest = Manifest.parse(manifestFileStream());
      Section section = manifest.getSection("com/manheim/simulcast/cache/Cache.class");
      assertEquals(2, section.size());
      String[] digests = section.getDigests();
      assertEquals(1, digests.length);
      assertEquals("SHA-256", digests[0]);

      String digest = section.getAttribute("SHA-256-Digest");
      assertEquals("y81kVgzNYH1L8b58IFVOQMS/Se1Jd1ihwd9All/O0xk=", digest);

   }

   @Test
   public void testDigestMainMethod() throws Exception
   {
      Manifest manifest = Manifest.parse(manifestFileStream());
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] digest = manifest.getMain().digest(md);
      assertEquals("KUQaWc0H7aS83+OjigPzkJT/fPgyZp7Zb4k9cvLoVOc=", Base64.getEncoder().encodeToString(digest));


      //Kds7VEe/DjHhdchwF3rRwRQUrwwHyMm92Nmi0dCZSZc=

   }

   @Test
   public void testDigestMethod() throws Exception
   {
      Manifest manifest = Manifest.parse(manifestFileStream());
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] digest = manifest.digest(md);
      assertEquals("Kds7VEe/DjHhdchwF3rRwRQUrwwHyMm92Nmi0dCZSZc=", Base64.getEncoder().encodeToString(digest));
   }











   private static final byte[] DATA = { (byte) 0x0D, (byte) 0x0A };

   @Test
   public void testEmptyManifest() throws Exception
   {
      Manifest.parse(new ByteArrayInputStream(DATA));
   }

   @Test
   public void testPartialManifest() throws Exception
   {
      Manifest.parse(load("PARTIAL.MF"));
   }

   @Test
   public void testCorruptHeaderManifest() throws Exception
   {
      IOException ex = assertThrows(IOException.class, () -> {
            Manifest.parse(load("CORRUPT.MF"));
         });
      assertEquals("invalid attribute", ex.getMessage());
      assertNull(ex.getCause());
   }

   @Test
   public void testCorruptSectionManifest() throws Exception
   {
      IOException ex = assertThrows(IOException.class, () -> {
         Manifest.parse(load("CORRUPT-SECTION.MF"));
      });
      assertEquals("invalid attribute", ex.getMessage());
      assertNull(ex.getCause());
   }

   @Test
   public void testDuplicateSectionManifest() throws Exception
   {
      Manifest.parse(load("DUPLICATE-SECTION.MF"));
   }

   @Test
   public void testGarbageManifest() throws Exception
   {
      IOException ex = assertThrows(IOException.class, () -> {
         Manifest.parse(load("GARBAGE.MF"));
      });
      assertEquals("invalid attribute", ex.getMessage());
      assertNull(ex.getCause());
   }





   
   private static InputStream manifestFileStream() throws Exception
   {
      return load("MANIFEST.MF");
   }

   private static byte[] manifestFileBytes() throws Exception
   {
      Path manifestPath = Paths.get("src","test", "resources", "MANIFEST.MF");
      return Files.readAllBytes(manifestPath);
   }

   private static InputStream load(String file) throws Exception
   {
      Path manifestPath = Paths.get("src","test", "resources", file);
      return Files.newInputStream(manifestPath);
   }
}