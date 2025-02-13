/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 1/24/2025
 */
package org.xpertss.jarsigner.jar;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.*;
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

   private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(JavaArchive.class);



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

   public int signatureCount()
   {
      return signatures.size();
   }

   /**
    * Returns a stream over the non-signature file entries in this archive.
    */
   public Stream<ZipEntry> entries()
   {
      return entries.stream();
   }

   public int entryCount()
   {
      return entries.size();
   }


   /**
    * Returns the InputStream for a given zip entry.
    *
    * @throws IOException If an I/O error occurs.
    */
   public InputStream getInputStream(ZipEntry e)
      throws IOException
   {
      return new BufferedInputStream(source.getInputStream(e));
   }



   public SignatureFile generateSignatureFile(String signame, MessageDigest md)
      throws IOException
   {
      Base64.Encoder encoder = Base64.getEncoder();
      String digestName = String.format("%s-Digest", md.getAlgorithm());
      Map<String,Section> sections = new LinkedHashMap<>();
      for(ZipEntry ze : entries) {
         Section section = getManifest().getSection(ze.getName());
         String current = section.getAttribute(digestName);
         try(InputStream in = getInputStream(ze)) {
            byte[] digest = ArchiveUtils.readDigest(md, in);
            String actual = encoder.encodeToString(digest);
            if(current == null || !current.equals(actual)) {
               section.setAttribute(digestName, actual);
            }
         }
         Section sigsec = section.digest(md);
         sections.put(sigsec.getName(), sigsec);
      }
      String mainDigest = encoder.encodeToString(getManifest().getMain().digest(md));
      String manifestDigest = encoder.encodeToString(getManifest().digest(md));
      Main main = Main.createSignature(manifestDigest, mainDigest, md.getAlgorithm());
      return new SignatureFile(signame, main, sections);
   }




   public static JavaArchive from(ZipFile source)
      throws IOException
   {
      return from(source, false);
   }

   /*
        NOTE: When parsing the manifest there are corruptions we skip over that would
        ultimately result in any existing signature files being invalid. We do not
        track those lenient parsing issues and as such do not reflect it in the modified
        state. We assume that when we generate the new signature file that will result in
        at least some of those being fixed and thus isModified will be true. But there is
        no guarantee of that.

        Examples of corruptions we ignore
          Sections that start off with a continuation rather than a Name
          Sections that order their attributes in such a way as Name is not first
          Attributes with no value
          Duplicate Attributes in a section
          Duplicate sections within a manifest
    */
   public static JavaArchive from(ZipFile source, boolean clean)
      throws IOException
   {
      Set<ZipEntry> signatures = new TreeSet<>((first, second) -> first.getName().compareTo(second.getName()));
      Set<ZipEntry> entries = new LinkedHashSet<>();
      Manifest manifest = new Manifest();
      boolean corrupt = true; // Assume corrupt until successful parse of manifest

      for(Enumeration<? extends ZipEntry> files = source.entries(); files.hasMoreElements(); ) {
         ZipEntry entry = files.nextElement();
         String name = entry.getName();
         if(ArchiveUtils.isArchiveSpecial(name)) {
            if(ArchiveUtils.isManifest(name)) {
               try {
                  manifest = Manifest.parse(source.getInputStream(entry), clean);
                  corrupt = false;
               } catch(CorruptManifestException cme) {
                  // TODO Do I just want to let this fail or continue on?
                  log.warn("Failed to parse existing manifest: " + cme.getMessage());
               }
            } else if(ArchiveUtils.isBlockOrSF(name)) {
               signatures.add(entry);
            } else {
               // Must be that SIG- file.. What to do with it
            }
         } else {
            entries.add(entry);
         }
      }

      // TODO Do I need this
      /*
      if(corrupt && !signatures.isEmpty()) {
         log.warn("Manifest updated, clearing existing signatures!");
         signatures.clear();
      }
       */
      return new JavaArchive(source, entries, signatures, manifest);
   }


}
