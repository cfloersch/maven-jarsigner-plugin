/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 1/25/2025
 */
package org.xpertss.jarsigner.jar;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.*;
import java.util.jar.JarFile;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static java.lang.String.*;

public class ArchiveUtils {

   private static final String META_INF = "META-INF/";
   private static final String SIG_PREFIX = META_INF + "SIG-";


   /**
    * Scans an archive for existing signatures.
    *
    * @param jarFile The archive to scan, must not be <code>null</code>.
    * @return <code>true</code>, if the archive contains at least one signature file; <code>false</code>, if the
    *         archive does not contain any signature files.
    * @throws IOException if scanning <code>jarFile</code> fails.
    */
   public static boolean isArchiveSigned(final Path jarFile)
      throws IOException
   {
      if (jarFile == null) throw new NullPointerException("jarFile");

      try (ZipInputStream in = zipStream(jarFile)) {
         boolean signed = false;

         for (ZipEntry ze = in.getNextEntry(); ze != null; ze = in.getNextEntry()) {
            if (isBlockOrSF(ze.getName())) {
               signed = true;
               break;
            }
         }

         return signed;
      }
   }


   /**
    * Returns true if the given name matches
    * . META-INF/*.SF
    * . META-INF/*.DSA
    * . META-INF/*.RSA
    * . META-INF/*.EC
    */
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

   /**
    * Returns true if the entry name represents the Manifest file
    */
   public static boolean isManifest(String name)
   {
      return name.equalsIgnoreCase(JarFile.MANIFEST_NAME);
   }

   /**
    * Returns true if the given entry name exists within the META-INF
    * directory or a subdirectory there-in.
    */
   public static boolean isMetaInfBased(String name)
   {
      String ucName = name.toUpperCase(Locale.ENGLISH);
      return ucName.startsWith(META_INF);
   }




   /**
    * Checks whether the specified file is a JAR file. For our purposes, a ZIP file is
    * a ZIP stream with at least one entry.
    *
    * @param file The file to check, must not be <code>null</code>.
    * @return <code>true</code> if the file looks like a ZIP file,
    *             <code>false</code> otherwise.
    */
   public static boolean isZipFile(final File file)
   {
      boolean result = false;

      try (ZipInputStream zis = zipStream(file.toPath())) {
         result = zis.getNextEntry() != null;
      } catch (Exception e) {
         // ignore, will fail below
      }

      return result;
   }


   /**
    * Utility method to read the contents of a ZipEntry and compute the digest
    * using the given {@link MessageDigest}
    *
    * @param md The message digest to use in the computation
    * @param inputStream The source stream to compute the digest on
    * @return The raw digest bytes
    * @throws IOException If an IO error occurs
    */
   public static byte[] readDigest(MessageDigest md, InputStream inputStream)
      throws IOException
   {
      Objects.requireNonNull(md, "md");
      Objects.requireNonNull(inputStream, "inputStream");
      md.reset();
      byte[] buffer = new byte[8192];
      while (inputStream.read(buffer) != -1) {
         md.update(buffer);
      }
      return md.digest();
   }

   /**
    * Copy the bytes from the given input stream to the given output stream.
    *
    * @return The number of bytes written
    * @throws IOException If an IO error occurs
    */
   public static long copy(final InputStream inputStream, final OutputStream outputStream)
      throws IOException
   {
      Objects.requireNonNull(inputStream, "inputStream");
      Objects.requireNonNull(outputStream, "outputStream");
      byte[] buffer = new byte[8192];
      long count = 0;
      int n;
      while (-1 != (n = inputStream.read(buffer))) {
         outputStream.write(buffer, 0, n);
         count += n;
      }
      return count;
   }


   /**
    * Parses an encoded manifest section (or main attributes) and returns an
    * ordered Map containing all of the named attributes.
    *
    * @param rawdata The raw encoded data including newline characters
    * @return Ordered map of the attributes
    * @throws IOException if an IO error occurs or an encoding error is encountered
    */
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
               if(previous == null) {
                  throw new CorruptManifestException("invalid continuation found");
               }
               String append = line.trim();
               attributes.computeIfPresent(previous,
                              (key, oldValue) ->
                                 format("%s%s", oldValue, append));
            } else {
               String[] nameValue = line.split(":\\s+");
               if(nameValue.length != 2) {
                  throw new CorruptManifestException("invalid attribute");
               }
               try {
                  validateAttributeName(nameValue[0]);
               } catch(IllegalArgumentException e) {
                  throw new CorruptManifestException("invalid attribute name");
               }
               if(attributes.put(nameValue[0], nameValue[1]) != null) {
                  throw new CorruptManifestException("duplicate attribute found");
               }
               previous = nameValue[0];
            }
         }
      }
      return attributes;
   }


   /**
    * Creates and returns the default main attributes for the given type.
    * The type should be either {@link Manifest#SIGNATURE_VERSION} or
    * {@link Manifest#MANIFEST_VERSION}
    */
   public static Map<String,String> createAttributes(String type)
   {
      // TODO Insert Xpertss-JarSigner and current version
      String version = System.getProperty("java.version");

      Map<String,String> attributes = new LinkedHashMap<>();
      attributes.put(type, "1.0");
      attributes.put(Manifest.CREATED_BY, version + " (Xpertss)");
      return attributes;
   }

   /**
    * Encodes the main attributes into a manifest file compliant byte array.
    */
   public static byte[] encodeAttributes(Map<String,String> attributes)
   {
      return encodeAttributes(null, attributes);
   }

   /**
    * Encodes a section attributes into a manifest file compliant byte array.
    * <p/>
    * Unlike the main attributes, sections always begin with a {@code Name}
    * attribute.
    *
    * @param name The {@code Name} attribute value
    * @param attributes The rest of the attributes to encode
    */
   public static byte[] encodeAttributes(String name, Map<String,String> attributes)
   {
      try(PrintOutputStream out = new PrintOutputStream(8192)) {
         if(name != null && !name.isEmpty()) print(out, "Name", name);
         attributes.forEach((key, value) -> { print(out, key, value); });
         out.newLine();
         return out.toByteArray();
      } catch(IOException e) {
         throw new InternalError("failure to close nothing");
      }
   }


   /**
    * Validates an attribute name for compliance.
    */
   public static void validateAttributeName(String name)
   {
      if(name == null || name.length() > 70 || name.isEmpty()) {
         throw new IllegalArgumentException("invalid attribute name");
      } else if(!Pattern.matches("^[a-zA-Z0-9_-]*$", name)) {
         throw new IllegalArgumentException("invalid attribute name");
      }
   }

   /**
    * Transforms the given input name, trimming it to 8 characters in
    * length, and replacing unsupported characters with underscores.
    *
    * @param sigfile The input name to clean
    */
   public static String cleanSigFileName(String sigfile)
   {
      if(sigfile.length() > 8) sigfile = sigfile.substring(0, 8);
      StringBuilder tmpSigFile = new StringBuilder(sigfile.length());
      for (int j = 0; j < sigfile.length(); j++) {
         char c = sigfile.charAt(j);
         if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                 (c == '-') || (c == '_'))) {
            // convert illegal characters from the alias to be _'s
            c = '_';
         }
         tmpSigFile.append(c);
      }
      return tmpSigFile.toString();
   }


   private static void print(PrintOutputStream out, String key, String value)
   {
      String line = format("%s: %s", key, value);
      if(line.length() > 70) {
         out.println(line.substring(0, 70));
         out.println(" " + line.substring(70));
      } else {
         out.println(line);
      }
   }

   private static ZipInputStream zipStream(Path path)
      throws IOException
   {
      return new ZipInputStream(new BufferedInputStream(Files.newInputStream(path)));
   }


   /**
    * Simple ByteArrayOutputStream that throws no errors, supports Charsets,
    * and newlines, unlike PrintStream.
    */
   private static class PrintOutputStream implements Closeable  {

      private static final byte[] NEWLINE = { (byte) 0x0D, (byte) 0x0A };

      private final int origSize;
      private byte[] buf;
      private int count;

      private Charset cs;

      private PrintOutputStream(int size)
      {
         this(size, StandardCharsets.UTF_8);
      }

      private PrintOutputStream(Charset cs)
      {
         this(1024, cs);
      }

      private PrintOutputStream(int size, Charset cs)
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
