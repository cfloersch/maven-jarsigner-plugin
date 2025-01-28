/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 1/24/2025
 */
package org.xpertss.jarsigner.jar;


import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

public final class Section {

   private byte[] rawbytes;

   private final Map<String,String> attributes;


   private Section(String name)
   {
      this.attributes = new LinkedHashMap<>();
      this.attributes.put("Name", Objects.requireNonNull(name, "name"));
   }

   private Section(byte[] rawbytes, Map<String,String> attributes)
   {
      this.rawbytes = rawbytes;
      this.attributes = attributes;
   }


   /**
    * Helper method to obtain the attribute identified as Name
    */
   public String getName()
   {
      return attributes.get("Name");
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
    */
   public void setAttribute(String attrName, String value)
   {
      // TODO Should I prevent modification of Name???
      attributes.put(attrName, value);
      rawbytes = null;
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
      return rawbytes == null;
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
    * Returns the raw bytes used to construct this section from a given manifest
    * file if they have not been modified. Otherwise, the attributes are re-encoded
    * and returned.
    * <p/>
    * This includes the lines continuations, new line chars, and trailing empty line.
    */
   public byte[] getEncoded()
   {
      if(rawbytes == null) rawbytes = ArchiveUtils.encodeAttributes(attributes);
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
      return (attributes.isEmpty()) ? null : new Section(rawbytes, attributes);
   }


}
