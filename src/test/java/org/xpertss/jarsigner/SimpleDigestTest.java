/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 1/24/2025
 */
package org.xpertss.jarsigner;

import org.junit.jupiter.api.Test;
import org.xpertss.jarsigner.jar.ArchiveUtils;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SimpleDigestTest {

   @Test
   public void digestManifestHeader() throws Exception
   {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] manifest = loadContent();
      int endOfHeader = findHeaderEnd(manifest, 0);
      md.update(manifest, 0, endOfHeader);
      byte[] digest = md.digest();
      String result = Base64.getEncoder().encodeToString(digest);
      assertEquals("KUQaWc0H7aS83+OjigPzkJT/fPgyZp7Zb4k9cvLoVOc=", result);

   }

   @Test
   public void digestManifest() throws Exception
   {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] manifest = loadContent();
      md.update(manifest, 0, manifest.length);
      byte[] digest = md.digest();
      String result = Base64.getEncoder().encodeToString(digest);
      assertEquals("Kds7VEe/DjHhdchwF3rRwRQUrwwHyMm92Nmi0dCZSZc=", result);
   }


   @Test
   public void digestManifestSection() throws Exception
   {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] manifest = loadContent();
      int endOfHeader = findHeaderEnd(manifest, 0);
      int endOfSection = findHeaderEnd(manifest, endOfHeader);

      assertNotEquals(manifest[endOfHeader], (byte) 0x0A);
      assertNotEquals(manifest[endOfHeader], (byte) 0x0A);
      assertEquals(manifest[endOfSection - 1], (byte) 0x0A);

      md.update(manifest, endOfHeader, endOfSection - endOfHeader);
      byte[] digest = md.digest();
      String result = Base64.getEncoder().encodeToString(digest);
      assertEquals("WHmcmNAoJPQ295M7raATOqQLnOHhfN1DLKZ0xwvyndA=", result);
   }


   @Test
   public void testEncodingVsLoaded() throws Exception
   {
      Map<String, String> attributes = new LinkedHashMap<>();
      attributes.put("SHA-256-Digest","y81kVgzNYH1L8b58IFVOQMS/Se1Jd1ihwd9All/O0xk=");
      byte[] encoded = ArchiveUtils.encodeAttributes("com/manheim/simulcast/cache/Cache.class", attributes);

      byte[] manifest = loadContent();
      int endOfHeader = findHeaderEnd(manifest, 0);
      int endOfSection = findHeaderEnd(manifest, endOfHeader);
      byte[] loaded = new byte[endOfSection - endOfHeader];
      System.arraycopy(manifest, endOfHeader, loaded, 0, loaded.length);

      assertTrue(Arrays.equals(encoded, loaded));
   }

   @Test
   public void testMultiLineEncoding()
   {
      Map<String, String> attributes = new LinkedHashMap<>();
      attributes.put("SHA-256-Digest","3qbfZ3CnHmSK1smtxKx2KI+3qOyfTvm7loN2WdG3qYU=");
      byte[] encoded = ArchiveUtils.encodeAttributes("com/manheim/simulcast/biddisplay/DefaultFlashingStrategy$LaneModelEventHandler.class", attributes);
      assertEquals(encoded[70], (byte) 0x0D);   // zero based
      assertEquals(encoded[71], (byte) 0x0A);
      assertEquals(encoded[72], (byte) 0x20);

   }


   private static byte[] loadContent() throws Exception
   {
      // JAR Manifest files are always encoded in UTF-8
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      try(InputStream in = SimpleDigestTest.class.getResourceAsStream("/MANIFEST.MF")) {
         int nRead;
         byte[] data = new byte[16384];
         while ((nRead = in.read(data, 0, data.length)) != -1) {
            baos.write(data, 0, nRead);
         }
         return baos.toByteArray();
      }
   }


   /**
    * Find the length of header inside bs. The header is a multiple (>=0)
    * lines of attributes plus an empty line. The empty line is included
    * in the header.
    */
   private int findHeaderEnd(byte[] bs, int start)
   {
      // Initial state true to deal with empty header
      boolean newline = true;     // just met a newline
      int len = bs.length;
      for (int i=start; i<len; i++) {
         switch (bs[i]) {
            case '\r':
               if (i < len - 1 && bs[i+1] == '\n') i++;
               // fallthrough
            case '\n':
               if (newline) return i+1;    //+1 to get length
               newline = true;
               break;
            default:
               newline = false;
         }
      }
      // If header end is not found, it means the MANIFEST.MF has only
      // the main attributes section and it does not end with 2 newlines.
      // Returns the whole length so that it can be completely replaced.
      return len;
   }





}
