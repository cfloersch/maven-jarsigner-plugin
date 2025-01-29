/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 1/24/2025
 */
package org.xpertss.jarsigner.jar;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Class that represents the main attributes of a Manifest or Signature file.
 */
public final class Main {


   private final Map<String,String> attributes;
   private byte[] rawbytes;
   private boolean modified = false;


   private Main(Map<String,String> attributes)
   {
      // TODO Validate this preserves order
      this.attributes = Collections.unmodifiableMap(attributes);
      this.modified = true;
   }

   private Main(byte[] rawbytes, Map<String,String> attributes)
   {
      this.rawbytes = rawbytes;
      this.attributes = attributes;
   }


   /**
    * Returns the attribute value for the given attribute name.
    */
   public String getAttribute(String attrName)
   {
      return attributes.get(attrName);
   }

   /**
    * Returns a stream over the attribute names in this main section.
    */
   public Stream<String> attributeNames()
   {
      return attributes.keySet().stream();
   }

   /**
    * Returns the number of attributes in this main section.
    */
   public int size()
   {
      return attributes.size();
   }

   public boolean isModified()
   {
      return modified;
   }

   /**
    * Given a MessageDigest this will encode the main section if needed and compute the
    * message digest. This is necessary for the X-Digest-Manifest-Main-Attributes
    * attribute in the SignatureFile.
    *
    * @param md The digest algorithm to use to compute the digest
    * @return The raw digest bytes for this Main attributes.
    */
   public byte[] digest(MessageDigest md)
   {
      md.reset();
      md.update(getEncoded());
      return md.digest();
   }


   /**
    * Return the encoded bytes representing this main sections attributes. This
    * will return the original bytes as they were parsed from the source manifest
    * if it exists and is unaltered. Otherwise, it encodes the attributes to be
    * written to file.
    */
   public byte[] getEncoded()
   {
      if(rawbytes == null) rawbytes = ArchiveUtils.encodeAttributes(null, attributes);
      return rawbytes;
   }


   /**
    * Create a default Main section to be used in a Manifest.
    */
   public static Main createManifest()
   {
      Map<String,String> attributes = ArchiveUtils.createAttributes(Manifest.MANIFEST_VERSION);
      return new Main(attributes);
   }

   /**
    * Create a Main section to be used in a Signature file, with the given manifest
    * digests,
    *
    * @param manifestDigest The base64 encoded manifest digest
    * @param manifestMainDigest The base64 encoded manifest main section digest
    * @param digestAlg The digest algorithm used to create the given digests
    */
   public static Main createSignature(String manifestDigest, String manifestMainDigest, String digestAlg)
   {
      Map<String,String> attributes = ArchiveUtils.createAttributes(Manifest.SIGNATURE_VERSION);
      attributes.put(String.format("%s-Digest-Manifest-Main-Attributes", digestAlg), manifestMainDigest);
      attributes.put(String.format("%s-Digest-Manifest", digestAlg), manifestDigest);
      return new Main(attributes);
   }


   /**
    * Parse the raw bytes of the Manifest main section into it's attributes
    * and return an instance of Main which encapsulates those.
    *
    * @param rawbytes The raw bytes of the main section to include line breaks
    * @throws IOException If the attributes are malformed, duplicate, etc
    */
   public static Main parse(byte[] rawbytes)
      throws IOException
   {
      Map<String,String> attributes = ArchiveUtils.parseAttributes(rawbytes);
      if(attributes.keySet().stream().noneMatch(HEADERS::contains)) {
         if(attributes.isEmpty())
            throw new CorruptManifestException("missing headers");
         throw new CorruptManifestException("missing version");
      }
      return new Main(rawbytes, attributes);
   }

   private static final Set<String> HEADERS = Stream.of(Manifest.SIGNATURE_VERSION, Manifest.MANIFEST_VERSION).collect(Collectors.toSet());






}
