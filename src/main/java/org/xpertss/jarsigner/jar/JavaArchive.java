/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 1/24/2025
 */
package org.xpertss.jarsigner.jar;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.NavigableSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarFile;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/*
  Creating Signed Jar
    Parse existing Zip into JavaArchive
      GenerateSignatureFile -> Should update manifest
      Get manifest -> Write to new JAR
      If manifest not modified
        Write all pre-existing signature files
      Write our new Signature File to Jar
      Generate Block file and write to Jar
      Loop through entries and write them one at a time
 */
public class JavaArchive {

   private final ZipFile source;
   private final Set<ZipEntry> entries;
   private final Set<ZipEntry> signatures;
   private final Manifest manifest;

   JavaArchive(ZipFile source, Set<ZipEntry> entries, Set<ZipEntry> signatures, Manifest manifest)
   {
      this.source = source;
      this.entries = entries;
      this.signatures = signatures;
      this.manifest = manifest;
   }


   public Manifest getManifest()
   {
      return manifest;
   }


   /**
    * Returns a stream over the signature file entries in this archive.
    * <p/>
    * These are generally written before the regular entries to the output archive.
    */
   public Stream<ZipEntry> signatures()
   {
      return signatures.stream();
   }

   /**
    * Returns a stream over the non-signature file entries in this archive.
    */
   public Stream<ZipEntry> entries()
   {
      return entries.stream();
   }

   public InputStream getInputStream(ZipEntry e)
      throws IOException
   {
      return source.getInputStream(e);
   }



   public SignatureFile generateSignatureFile(String signame, MessageDigest md)
   {
      // Loop through non-signature entries creating SignatureFile sections, updating manifest as necessary
         // If manifest is missing an entry add it
         // If manifest has wrong digest, update it
         // If manifest has digests of different DigestAlg, add new digest
      // Finally create signature Main
      return null;
   }





   public static JavaArchive from(ZipFile source)
      throws IOException
   {
      Set<ZipEntry> signatures = new TreeSet<>((first, second) -> first.getName().compareTo(second.getName()));
      Set<ZipEntry> entries = new LinkedHashSet<>();
      Manifest manifest = null;

      for(Enumeration<? extends ZipEntry> files = source.entries(); files.hasMoreElements(); ) {
         ZipEntry entry = files.nextElement();
         String name = entry.getName();
         if(ArchiveUtils.isArchiveSpecial(name)) {
            if(JarFile.MANIFEST_NAME.equalsIgnoreCase(name)) {
               manifest = Manifest.parse(source.getInputStream(entry));
            } else if(ArchiveUtils.isBlockOrSF(name)) {
               signatures.add(entry);
            } else {
               // Must be that SIG- file.. What to do with it
            }
         } else {
            entries.add(entry);
         }
      }
      return new JavaArchive(source, entries, signatures, manifest);
   }


}
