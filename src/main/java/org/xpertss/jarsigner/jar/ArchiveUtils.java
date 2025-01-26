/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 1/25/2025
 */
package org.xpertss.jarsigner.jar;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.jar.JarFile;

import static java.lang.String.*;

public class ArchiveUtils {

   private static final String META_INF = "META-INF/";
   private static final String SIG_PREFIX = META_INF + "SIG-";



   public static boolean isBlockOrSF(String name)
   {
      String ucName = name.toUpperCase(Locale.ENGLISH);
      if(ucName.startsWith(META_INF) && ucName.indexOf("/") == ucName.lastIndexOf("/")) {
         // we currently only support ECDSA, DSA, and RSA PKCS7 blocks
         return ucName.endsWith(".SF") || ucName.endsWith(".DSA")
                  || ucName.endsWith(".RSA") || ucName.endsWith(".EC");
      }
      return false;
   }

   /**
    * archive special files include:
    * . META-INF/MANIFEST.MF
    * . META-INF/SIG-*
    * . META-INF/*.SF
    * . META-INF/*.DSA
    * . META-INF/*.RSA
    * . META-INF/*.EC
    */
   public static boolean isArchiveSpecial(String name)
   {
      String ucName = name.toUpperCase(Locale.ENGLISH);
      if(ucName.equals(JarFile.MANIFEST_NAME)) return true;
      if(ucName.startsWith(META_INF) && ucName.indexOf("/") == ucName.lastIndexOf("/")) {
         return (ucName.startsWith(SIG_PREFIX) || isBlockOrSF(name));
      }
      return false;
   }


   public static boolean isMetaInfBased(String name)
   {
      String ucName = name.toUpperCase(Locale.ENGLISH);
      return ucName.startsWith(META_INF);
   }





   public static Map<String,String> parseAttributes(byte[] rawdata)
      throws IOException
   {
      Map<String,String> attributes = new LinkedHashMap<>();
      InputStream in = new ByteArrayInputStream(rawdata);
      Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8);
      String previous = null;
      try(BufferedReader br = new BufferedReader(reader)) {
         String line;
         while((line = br.readLine()) != null) {
            if(line.isEmpty()) break;
            if(line.startsWith(" ")) {
               String append = line.trim();
               attributes.computeIfPresent(previous,
                              (key, oldValue) ->
                                 format("%s%s", oldValue, append));
            } else {
               String[] nameValue = line.split(":\\s+");
               if(nameValue.length != 2) {
                  throw new CorruptManifestException("invalid attribute");
               }
               if(attributes.put(nameValue[0], nameValue[1]) != null) {
                  // resulting manifest will be modified (signatures invalid)
                  throw new CorruptManifestException("duplicate attribute found");
               }
               previous = nameValue[0];
            }
         }
      }
      return attributes;
   }

   public static Map<String,String> createAttributes(String type)
   {
      // TODO Insert Xpertss-JarSigner and current version
      String version = System.getProperty("java.version");

      Map<String,String> attributes = new LinkedHashMap<>();
      attributes.put(type, "1.0");
      attributes.put(Manifest.CREATED_BY, version + " (Xpertss)");
      return attributes;
   }
   
   public static byte[] encodeAttributes(Map<String,String> attributes)
   {
      try(BufferedOutputStream out = new BufferedOutputStream(8192)) {
         attributes.forEach((key, value) -> {
            String line = format("%s: %s", key, value);
            if(line.length() > 70) {
               out.println(line.substring(0, 70));
               out.println(" " + line.substring(70));
            } else {
               out.println(line);
            }
         });
         out.newLine();
         return out.toByteArray();
      } catch(IOException e) {
         throw new InternalError("failure to close nothing");
      }
   }


   /**
    * Simple ByteArrayOutputStream that throws no errors, supports Charsets,
    * and newlines, unlike PrintStream.
    */
   private static class BufferedOutputStream implements Closeable  {

      private static final byte[] NEWLINE = { (byte) 0x0D, (byte) 0x0A };

      private final int origSize;
      private byte[] buf;
      private int count;

      private Charset cs;

      private BufferedOutputStream(int size)
      {
         this(size, StandardCharsets.UTF_8);
      }

      private BufferedOutputStream(Charset cs)
      {
         this(1024, cs);
      }

      private BufferedOutputStream(int size, Charset cs)
      {
         if(size < 0) throw new IllegalArgumentException("Negative initial size: " + size);
         this.origSize = size;
         this.buf = new byte[size];
         this.cs = cs;
      }

      private void ensureCapacity(int minCapacity) {
         // overflow-conscious code
         if (minCapacity - buf.length > 0)
            grow(minCapacity);
      }

      private static final int MAX_ARRAY_SIZE = Integer.MAX_VALUE - 8;

      private void grow(int minCapacity)
      {
         // overflow-conscious code
         int oldCapacity = buf.length;
         int newCapacity = oldCapacity << 1;
         if (newCapacity - minCapacity < 0)
            newCapacity = minCapacity;
         if (newCapacity - MAX_ARRAY_SIZE > 0)
            newCapacity = hugeCapacity(minCapacity);
         buf = Arrays.copyOf(buf, newCapacity);
      }


      private static int hugeCapacity(int minCapacity)
      {
         if (minCapacity < 0) // overflow
            throw new OutOfMemoryError();
         return (minCapacity > MAX_ARRAY_SIZE) ?
            Integer.MAX_VALUE :
            MAX_ARRAY_SIZE;
      }



      public void println(String line)
      {
         write(line.getBytes(cs));
         newLine();
      }


      public void write(byte[] data)
      {
         write(data, 0, data.length);
      }

      public void write(byte[] b, int off, int len)
      {
         if ((off < 0) || (off > b.length) || (len < 0) ||
            ((off + len) - b.length > 0)) {
            throw new IndexOutOfBoundsException();
         }
         ensureCapacity(count + len);
         System.arraycopy(b, off, buf, count, len);
         count += len;
      }

      public void newLine()
      {
         write(NEWLINE, 0, 2);
      }



      public byte[] toByteArray()
      {
         return Arrays.copyOf(buf, count);
      }

      public void writeTo(OutputStream out)
         throws IOException
      {
         out.write(buf, 0, count);
      }


      public int size() {
         return count;
      }


      @Override
      public void close()
         throws IOException
      {
         this.buf = new byte[origSize];
         count = 0;
      }

   }

}
