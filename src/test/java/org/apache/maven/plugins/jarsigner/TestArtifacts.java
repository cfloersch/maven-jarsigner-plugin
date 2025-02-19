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
package org.apache.maven.plugins.jarsigner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;

/**
 * Test utility class to create Artifact objects, jar file or other files that Maven attaches to a project
 */
class TestArtifacts {
    static final String TEST_GROUPID = "org.test-group";
    static final String TEST_ARTIFACTID = "test-artifact";
    static final String TEST_VERSION = "9.10.2";
    static final String TEST_TYPE = "jar";
    static final String TEST_CLASSIFIER = "";

    static Artifact createArtifact(Path file) throws IOException {
        return createArtifact(file, TEST_TYPE, TEST_CLASSIFIER);
    }

    static Artifact createArtifact(Path file, String type, String classifier) throws IOException {
        Artifact artifact = new DefaultArtifact(
                TEST_GROUPID, TEST_ARTIFACTID, TEST_VERSION, Artifact.SCOPE_COMPILE, type, classifier, null);
        artifact.setFile(file.toFile());
        return artifact;
    }

    static Artifact createJarArtifact(Path directory, String filename) throws IOException {
        return createJarArtifact(directory, filename, TEST_CLASSIFIER);
    }

    public static Artifact createJarArtifact(Path directory, String filename, String classifier) throws IOException {
        return createJarArtifact(directory, filename, classifier, TEST_TYPE);
    }

    public static Artifact createJarArtifact(Path directory, String filename, String classifier, String type)
            throws IOException {
        Path file = directory.resolve(filename);
        createDummyZipFile(file);
        return createArtifact(file, type, classifier);
    }

    static Artifact createPomArtifact(Path directory, String filename) throws IOException {
        Path file = directory.resolve(filename);
        createDummyXMLFile(file);
        return createArtifact(file, TEST_TYPE, "");
    }

    /** Create a dummy JAR/ZIP file, enough to pass ZipInputStream.getNextEntry() */
    static Path createDummyZipFile(Path zipFile) throws IOException {
        try (ZipOutputStream zipOutputStream = new ZipOutputStream(Files.newOutputStream(zipFile, StandardOpenOption.CREATE_NEW))) {
            ZipEntry entry = new ZipEntry("dummy-entry.txt");
            zipOutputStream.putNextEntry(entry);
        }
        return zipFile;
    }

    /** Create a dummy signed JAR, enough to pass JarSignerUtil.isArchiveSigned() */
    static Path createDummySignedJarFile(Path jarFile) throws IOException {
        try (ZipOutputStream zipOutputStream = new ZipOutputStream(Files.newOutputStream(jarFile, StandardOpenOption.CREATE_NEW))) {
            ZipEntry entry = new ZipEntry("dummy-entry.txt");
            zipOutputStream.putNextEntry(entry);
            zipOutputStream.putNextEntry(new ZipEntry("META-INF/dummy.RSA"));
        }

        return jarFile;
    }

    /** Create a dummy XML file, for example to simulate a pom.xml file */
    static Path createDummyXMLFile(Path xmlFile) throws IOException {
        Files.write(xmlFile, "<project/>".getBytes());
        return xmlFile;
    }
}
