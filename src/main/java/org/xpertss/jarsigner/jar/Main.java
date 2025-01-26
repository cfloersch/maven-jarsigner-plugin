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
import java.util.stream.Stream;

public class Main {


   private final Map<String,String> attributes;
   private byte[] rawbytes;


   private Main(Map<String,String> attributes)
   {
      // TODO Validate this preserves order
      this.attributes = Collections.unmodifiableMap(attributes);
   }

   private Main(byte[] rawbytes, Map<String,String> attributes)
   {
      this.rawbytes = rawbytes;
      this.attributes = attributes;
   }



   public String getAttribute(String attrName)
   {
      return attributes.get(attrName);
   }

   public Stream<String> attributeKeys()
   {
      return attributes.keySet().stream();
   }

   public int size()
   {
      return attributes.size();
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

   
   public byte[] getEncoded()
   {
      if(rawbytes == null) rawbytes = ArchiveUtils.encodeAttributes(attributes);
      return rawbytes;
   }




   
   public static Main createManifest()
   {
      Map<String,String> attributes = ArchiveUtils.createAttributes(Manifest.MANIFEST_VERSION);
      return new Main(attributes);
   }

   public static Main createSignature(String manifestDigest, String manifestMainDigest, String digestAlg)
   {
      Map<String,String> attributes = ArchiveUtils.createAttributes(Manifest.SIGNATURE_VERSION);
      attributes.put(String.format("%s-Digest-Manifest-Main-Attributes", digestAlg), manifestMainDigest);
      attributes.put(String.format("%s-Digest-Manifest", digestAlg), manifestDigest);
      return new Main(attributes);
   }



   public static Main parse(byte[] rawbytes)
      throws IOException
   {
      Map<String,String> attributes = ArchiveUtils.parseAttributes(rawbytes);
      return (attributes.isEmpty()) ? null : new Main(rawbytes, attributes);
   }







}
