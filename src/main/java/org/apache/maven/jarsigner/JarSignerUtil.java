/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.maven.jarsigner;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import org.apache.commons.io.IOUtils;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;

/**
 * Useful methods.
 *
 * @author Tony Chemit
 * @since 1.0
 */
public class JarSignerUtil {

    private JarSignerUtil() {
        // static class
    }

    /**
     * Checks whether the specified file is a JAR file. For our purposes, a ZIP file is a ZIP stream with at least one
     * entry.
     *
     * @param file The file to check, must not be <code>null</code>.
     * @return <code>true</code> if the file looks like a ZIP file, <code>false</code> otherwise.
     */
    public static boolean isZipFile(final File file) {
        boolean result = false;

        try (ZipInputStream zis = new ZipInputStream(Files.newInputStream(file.toPath()))) {
            result = zis.getNextEntry() != null;
        } catch (Exception e) {
            // ignore, will fail below
        }

        return result;
    }

    /**
     * Removes any existing signatures from the specified JAR file. We will stream from the input JAR directly to the
     * output JAR to retain as much metadata from the original JAR as possible.
     *
     * @param jarFile The JAR file to unsign, must not be <code>null</code>.
     * @throws IOException when error occurs during processing the file
     */
    public static void unsignArchive(Path jarFile) throws IOException {

        String filename = jarFile.getFileName().toString();
        Path unsignedPath = jarFile.toAbsolutePath().resolveSibling(filename + ".unsigned");

        try (ZipInputStream zis = new ZipInputStream(new BufferedInputStream(Files.newInputStream(jarFile)));
                ZipOutputStream zos =
                        new ZipOutputStream(new BufferedOutputStream(Files.newOutputStream(unsignedPath, StandardOpenOption.CREATE_NEW)))) {
            for (ZipEntry ze = zis.getNextEntry(); ze != null; ze = zis.getNextEntry()) {
                if (isSignatureFile(ze.getName())) {
                    continue;
                }

                zos.putNextEntry(new ZipEntry(ze.getName()));

                if (isManifestFile(ze.getName())) {

                    // build a new manifest while removing all digest entries
                    // see https://jira.codehaus.org/browse/MSHARED-314
                    Manifest oldManifest = new Manifest(zis);
                    Manifest newManifest = buildUnsignedManifest(oldManifest);
                    newManifest.write(zos);

                    continue;
                }

                IOUtils.copy(zis, zos);
            }
        }
        Files.move(unsignedPath, jarFile, REPLACE_EXISTING);
    }

    /**
     * Build a new manifest from the given one, removing any signing information inside it.
     *
     * This is done by removing any attributes containing some digest information.
     * If an entry has then no more attributes, then it will not be written in the result manifest.
     *
     * @param manifest manifest to clean
     * @return the build manifest with no digest attributes
     * @since 1.3
     */
    protected static Manifest buildUnsignedManifest(Manifest manifest) {
        Manifest result = new Manifest(manifest);
        result.getEntries().clear();

        for (Map.Entry<String, Attributes> manifestEntry : manifest.getEntries().entrySet()) {
            Attributes oldAttributes = manifestEntry.getValue();
            Attributes newAttributes = new Attributes();

            for (Map.Entry<Object, Object> attributesEntry : oldAttributes.entrySet()) {
                String attributeKey = String.valueOf(attributesEntry.getKey());
                if (!attributeKey.endsWith("-Digest")) {
                    // can add this attribute
                    newAttributes.put(attributesEntry.getKey(), attributesEntry.getValue());
                }
            }

            if (!newAttributes.isEmpty()) {
                // can add this entry
                result.getEntries().put(manifestEntry.getKey(), newAttributes);
            }
        }

        return result;
    }

    /**
     * Scans an archive for existing signatures.
     *
     * @param jarFile The archive to scan, must not be <code>null</code>.
     * @return <code>true</code>, if the archive contains at least one signature file; <code>false</code>, if the
     *         archive does not contain any signature files.
     * @throws IOException if scanning <code>jarFile</code> fails.
     */
    public static boolean isArchiveSigned(final Path jarFile) throws IOException {
        if (jarFile == null) {
            throw new NullPointerException("jarFile");
        }

        try (ZipInputStream in = new ZipInputStream(new BufferedInputStream(Files.newInputStream(jarFile)))) {
            boolean signed = false;

            for (ZipEntry ze = in.getNextEntry(); ze != null; ze = in.getNextEntry()) {
                if (isSignatureFile(ze.getName())) {
                    signed = true;
                    break;
                }
            }

            return signed;
        }
    }

    /**
     * Checks whether the specified JAR file entry denotes a signature-related file, i.e. matches
     * <code>META-INF/*.SF</code>, <code>META-INF/*.DSA</code>, <code>META-INF/*.RSA</code> or
     * <code>META-INF/*.EC</code>.
     *
     * @param entryName The name of the JAR file entry to check, must not be <code>null</code>.
     * @return <code>true</code> if the entry is related to a signature, <code>false</code> otherwise.
     */
    protected static boolean isSignatureFile(String entryName) {
        if (entryName.regionMatches(true, 0, "META-INF", 0, 8)) {
            entryName = entryName.replace('\\', '/');

            if (entryName.indexOf('/') == 8 && entryName.lastIndexOf('/') == 8) {
                return endsWithIgnoreCase(entryName, ".SF")
                        || endsWithIgnoreCase(entryName, ".DSA")
                        || endsWithIgnoreCase(entryName, ".RSA")
                        || endsWithIgnoreCase(entryName, ".EC");
            }
        }
        return false;
    }

    protected static boolean isManifestFile(String entryName) {
        if (entryName.regionMatches(true, 0, "META-INF", 0, 8)) {
            entryName = entryName.replace('\\', '/');

            if (entryName.indexOf('/') == 8 && entryName.lastIndexOf('/') == 8) {
                return endsWithIgnoreCase(entryName, "/MANIFEST.MF");
            }
        }
        return false;
    }

    private static boolean endsWithIgnoreCase(String str, String searchStr) {
        return str.regionMatches(true, str.length() - searchStr.length(), searchStr, 0, searchStr.length());
    }
}
