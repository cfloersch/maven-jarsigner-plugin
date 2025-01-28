package org.xpertss.jarsigner.jar;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

import static org.junit.jupiter.api.Assertions.*;

/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 1/28/2025
 */
class ArchiveUtilsTest {

   @Test
   void testUnsignArchive() throws Exception {

      Path target = prepareTestJar("javax.persistence_2.0.5.v201212031355.jar");

      assertTrue(ArchiveUtils.isArchiveSigned(target));

      // check that manifest contains some digest attributes
      java.util.jar.Manifest originalManifest = readManifest(target);
      assertTrue(containsDigest(originalManifest));

      java.util.jar.Manifest originalCleanManifest = ArchiveUtils.buildUnsignedManifest(originalManifest);
      assertFalse(containsDigest(originalCleanManifest));

      assertEquals(originalCleanManifest, ArchiveUtils.buildUnsignedManifest(originalCleanManifest));

      ArchiveUtils.unsignArchive(target);

      assertFalse(ArchiveUtils.isArchiveSigned(target));

      // check that manifest has no digest entry
      // see https://issues.apache.org/jira/browse/MSHARED-314
      java.util.jar.Manifest manifest = readManifest(target);

      java.util.jar.Manifest cleanManifest = ArchiveUtils.buildUnsignedManifest(manifest);
      assertFalse(containsDigest(cleanManifest));

      assertEquals(manifest, cleanManifest);
      assertEquals(manifest, originalCleanManifest);
   }

   private java.util.jar.Manifest readManifest(Path file) throws IOException
   {
      JarFile jarFile = new JarFile(file.toFile());

      java.util.jar.Manifest manifest = jarFile.getManifest();

      jarFile.close();

      return manifest;
   }

   private boolean containsDigest(Manifest manifest) {
      for (Map.Entry<String, Attributes> entry : manifest.getEntries().entrySet()) {
         Attributes attr = entry.getValue();

         for (Map.Entry<Object, Object> objectEntry : attr.entrySet()) {
            String attributeKey = String.valueOf(objectEntry.getKey());
            if (attributeKey.endsWith("-Digest")) {
               return true;
            }
         }
      }
      return false;
   }

   protected Path prepareTestJar(String filename) throws IOException {
      Path source = Paths.get("src", "test", filename);
      Path target = Paths.get("target", filename);

      if (Files.exists(target)) {
         FileUtils.forceDelete(target.toFile());
      }

      Files.createDirectories(target.getParent());
      Files.copy(
         source,
         target,
         StandardCopyOption.REPLACE_EXISTING,
         StandardCopyOption.COPY_ATTRIBUTES,
         LinkOption.NOFOLLOW_LINKS);

      return target;
   }


}