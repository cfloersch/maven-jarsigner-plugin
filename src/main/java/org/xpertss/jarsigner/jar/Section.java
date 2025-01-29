/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 1/24/2025
 */
package org.xpertss.jarsigner.jar;


import java.io.IOException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

public final class Section {

   private byte[] rawbytes;
   private boolean modified;

   private final Map<String,String> attributes;
   private final String name;


   private Section(String name)
   {
      ArchiveUtils.validateAttributeName(name);
      this.attributes = new LinkedHashMap<>();
      this.name = Objects.requireNonNull(name, "name");
      this.modified = true;
   }

   private Section(String name, Map<String,String> attributes)
   {
      ArchiveUtils.validateAttributeName(name);
      this.name = Objects.requireNonNull(name, "name");
      this.attributes = attributes;
      this.modified = true;
   }

   private Section(byte[] rawbytes, String name, Map<String,String> attributes)
   {
      this.name = Objects.requireNonNull(name, "name");
      this.rawbytes = rawbytes;
      this.attributes = attributes;
   }


   /**
    * Helper method to obtain the attribute identified as Name
    */
   public String getName()
   {
      return name;
   }


   /**
    * Return the attribute value associated with the given attribute name.
    */
   public String getAttribute(String attrName)
   {
      return attributes.get(attrName);
   }

   /**
    * Return a stream over the attribute names in this section to include
    * {@code Name}
    */
   public Stream<String> attributeNames()
   {
      return attributes.keySet().stream();
   }


   /**
    * Set an attribute with the given name. This mutation will mark the
    * section as modified, which will ultimately invalidate any existing
    * signature.
    * <p/>
    * Throws IllegalArgumentException if you supply an attribute named
    * {@code Name}.
    */
   public void setAttribute(String attrName, String value)
   {
      if("Name".equalsIgnoreCase(attrName))
         throw new IllegalArgumentException("Attribute Name is reserved");
      attributes.put(attrName, value);
      modified = true;
      rawbytes = null;
   }

   public void clean()
   {
      attributes.keySet().removeIf(s -> s.endsWith("-Digest"));
      rawbytes = null;
      modified = true;
   }

   /**
    * Return the number of attributes in this section including the Name
    * attribute.
    */
   public int size()
   {
      return attributes.size();
   }


   /**
    * Returns {@code true} if any of the attributes in this section have been
    * modified or added.
    */
   public boolean isModified()
   {
      return modified;
   }


   /**
    * Helper method to get the list of digest algorithms for which digests
    * have been set.
    */
   public String[] getDigests()
   {
      return attributes.keySet().stream()
                  .filter(s -> s.endsWith("-Digest"))
                  .map(s -> s.substring(0, s.length() - 7))
                  .toArray(String[]::new);
   }

   /**
    * Create a signature file section from this manifest section, digesting
    * the current bytes and adding that attribute to the returned section.
    *
    * @param md The message digest to use in creating signature digest
    */
   public Section digest(MessageDigest md)
   {
      String digestName = String.format("%s-Digest", md.getAlgorithm());

      md.reset();
      md.update(getEncoded());
      Map<String,String> attributes = new LinkedHashMap<>();
      attributes.put(digestName, Base64.getEncoder().encodeToString(md.digest()));
      return new Section(name, attributes);
   }

   /**
    * Returns the raw bytes used to construct this section from a given manifest
    * file if they have not been modified. Otherwise, the attributes are re-encoded
    * and returned.
    * <p/>
    * This includes the lines continuations, new line chars, and trailing empty line.
    */
   public byte[] getEncoded()
   {
      if(rawbytes == null) rawbytes = ArchiveUtils.encodeAttributes(name, attributes);
      return rawbytes;
   }


   /**
    * Create a new Section with the given Name.
    */
   public static Section create(String name)
   {
      return new Section(name);
   }

   /**
    * Parse a section from an existing file. The rawbytes should include line breaks
    * and empty terminating line.
    *
    * @throws IOException If the given bytes have malformed or duplicate attributes
    */
   public static Section parse(byte[] rawbytes)
      throws IOException
   {
      Map<String,String> attributes = ArchiveUtils.parseAttributes(rawbytes);
      String name = attributes.remove("Name");
      return (attributes.isEmpty()) ? null : new Section(rawbytes, name, attributes);
   }


}
