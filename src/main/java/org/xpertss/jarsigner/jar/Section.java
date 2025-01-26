/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 1/24/2025
 */
package org.xpertss.jarsigner.jar;

import java.io.IOException;
import java.util.Map;
import java.util.stream.Stream;

public class Section {

   private byte[] rawbytes;

   private final Map<String,String> attributes;

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


   public String getAttribute(String attrName)
   {
      return attributes.get(attrName);
   }

   public Stream<String> attributeKeys()
   {
      return attributes.keySet().stream();
   }


   public void setAttribute(String attrName, String value)
   {
      attributes.put(attrName, value);
      rawbytes = null;
   }

   public int size()
   {
      return attributes.size();
   }


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



   public byte[] getEncoded()
   {
      if(rawbytes == null) rawbytes = ArchiveUtils.encodeAttributes(attributes);
      return rawbytes;
   }



   public static Section parse(byte[] rawbytes)
      throws IOException
   {
      Map<String,String> attributes = ArchiveUtils.parseAttributes(rawbytes);
      return (attributes.isEmpty()) ? null : new Section(rawbytes, attributes);
   }


}
