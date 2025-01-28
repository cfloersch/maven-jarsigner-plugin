/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 1/24/2025
 */
package org.xpertss.jarsigner.jar;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Stream;

public final class Manifest {


   /**
    * Attribute Name for <code>Manifest-Version</code>. This attribute indicates the version number
    * of the manifest standard to which a JAR file's manifest conforms.
    */
   public static final String MANIFEST_VERSION = "Manifest-Version";

   /**
    * Attribute Name for <code>Signature-Version</code> manifest attribute used when signing JAR files.
    */
   public static final String SIGNATURE_VERSION = "Signature-Version";

   /**
    * Attribute Name for <code>Created-By</code> manifest attribute that identifies the application that
    * created it.
    */
   public static final String CREATED_BY = "Created-By";

   /**
    * Attribute Name for <code>Content-Type</code>  manifest attribute.
    */
   public static final String CONTENT_TYPE = "Content-Type";

   /**
    * Attribute Name for <code>Class-Path</code>  manifest attribute. Bundled extensions can use this
    * attribute  to find other JAR files containing needed classes.
    */
   public static final String CLASS_PATH = "Class-Path";

   /**
    * Attribute Name for <code>Main-Class</code> manifest  attribute used for launching applications
    * packaged in JAR files.  The <code>Main-Class</code> attribute is used in conjunction  with the
    * <code>-jar</code> command-line option of the  <tt>java</tt> application launcher.
    */
   public static final String MAIN_CLASS = "Main-Class";

   /**
    * Attribute Name for <code>Sealed</code> manifest attribute  used for sealing.
    */
   public static final String SEALED = "Sealed";

   /**
    * Attribute Name for <code>Extension-List</code> manifest attribute  used for declaring dependencies on
    * installed extensions.
    */
   public static final String EXTENSION_LIST = "Extension-List";

   /**
    * Attribute Name for <code>Extension-Name</code> manifest attribute  used for declaring dependencies on
    * installed extensions.
    */
   public static final String EXTENSION_NAME = "Extension-Name";

   /**
    * Attribute Name for <code>Implementation-Title</code>  manifest attribute used for package versioning.
    */
   public static final String IMPLEMENTATION_TITLE = "Implementation-Title";

   /**
    * Attribute Name for <code>Implementation-Version</code>  manifest attribute used for package versioning.
    */
   public static final String IMPLEMENTATION_VERSION = "Implementation-Version";

   /**
    * Attribute Name for <code>Implementation-Vendor</code>  manifest attribute used for package versioning.
    */
   public static final String IMPLEMENTATION_VENDOR = "Implementation-Vendor";


   /**
    * Attribute Name for <code>Specification-Title</code>  manifest attribute used for package versioning.
    */
   public static final String SPECIFICATION_TITLE = "Specification-Title";

   /**
    * Attribute Name for <code>Specification-Version</code>  manifest attribute used for package versioning.
    */
   public static final String SPECIFICATION_VERSION = "Specification-Version";

   /**
    * Attribute Name for <code>Specification-Vendor</code>  manifest attribute used for package versioning.
    */
   public static final String SPECIFICATION_VENDOR = "Specification-Vendor";




   private final Main main;
   private final Map<String, Section> sections;


   private boolean modified = false;

   public Manifest()
   {
      this(null, new LinkedHashMap<>());
   }

   Manifest(Main main, Map<String, Section> sections)
   {
      if(main == null) {
         this.main = Main.createManifest();
         this.modified = true;
      } else {
         this.main = main;
      }
      this.sections = sections;
   }

   

   public Main getMain()
   {
      return main;
   }

   public Section getSection(String name)
   {
      return sections.get(name);
   }

   public Stream<Section> sections()
   {
      return sections.values().stream();
   }


   public void addSection(Section section)
   {
      sections.put(section.getName(), section);
      modified = true;
   }

   public int size()
   {
      return sections.size();
   }


   /**
    * Will indicate that the manifest was modified and that the existing signatures
    * will no longer be valid.
    */
   public boolean isModified()
   {
      return modified || sections.values().stream().anyMatch(Section::isModified);
   }


   /**
    * Return the digest for the entire manifest using the given algorithm.
    */
   public byte[] digest(MessageDigest md)
   {
      md.reset();
      md.update(main.getEncoded());
      for(Section section : sections.values()) {
         md.update(section.getEncoded());
      }
      // Returns the digest for the entire file
      return md.digest();
   }


   /**
    * Write the manifest out to the given output stream.
    */
   public void writeTo(OutputStream out)
      throws IOException
   {
      out.write(main.getEncoded());
      for(Section section : sections.values()) {
         out.write(section.getEncoded());
      }
      out.flush();
   }


   /**
    * Read the given input stream and parse the contents into a Manifest object.
    */
   public static Manifest parse(InputStream in)
      throws IOException
   {
      Map<String,Section> sections = new LinkedHashMap<>();
      Main main = null;

      try(BufferedInputStream bin = new BufferedInputStream(in)) {
         byte[] mainBytes = findNextSection(bin);
         main = Main.parse(mainBytes);
         while(main != null) {
            byte[] sectionBytes = findNextSection(bin);
            Section section = Section.parse(sectionBytes);
            if(section == null) break;
            if(sections.put(section.getName(), section) != null) {
               throw new CorruptManifestException("duplicate section found");
            }
         }
      }
      return new Manifest(main, sections);
   }




   private static byte[] findNextSection(InputStream in) throws IOException {
      ByteArrayOutputStream baos = new ByteArrayOutputStream(1024);
      int prev = -1; // Store the previous byte
      int current;
      int count = 0;

      while ((current = in.read()) != -1) {
         baos.write(current);

         if (current != '\r' && current != '\n') count = 0;
         if (prev == '\r' && current == '\n') count++;


         if (count == 2 || (prev == '\n' && current == '\n') || (prev == '\r' && current == '\r')) {
            return baos.toByteArray();
         }

         prev = current;
      }

      // If no double line break found, return everything read (assuming single section)
      return baos.toByteArray();
   }

}
