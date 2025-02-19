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

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Created on 11/8/13.
 *
 * @author Tony Chemit
 * @since 1.1
 */
class JarSignerUtilTest extends AbstractJarSignerTest {

    @Test
    void testUnsignArchive() throws Exception {

        Path target = prepareTestJar("javax.persistence_2.0.5.v201212031355.jar");

        assertTrue(JarSignerUtil.isArchiveSigned(target));

        // check that manifest contains some digest attributes
        Manifest originalManifest = readManifest(target);
        assertTrue(containsDigest(originalManifest));

        Manifest originalCleanManifest = JarSignerUtil.buildUnsignedManifest(originalManifest);
        assertFalse(containsDigest(originalCleanManifest));

        assertEquals(originalCleanManifest, JarSignerUtil.buildUnsignedManifest(originalCleanManifest));

        JarSignerUtil.unsignArchive(target);

        assertFalse(JarSignerUtil.isArchiveSigned(target));

        // check that manifest has no digest entry
        // see https://issues.apache.org/jira/browse/MSHARED-314
        Manifest manifest = readManifest(target);

        Manifest cleanManifest = JarSignerUtil.buildUnsignedManifest(manifest);
        assertFalse(containsDigest(cleanManifest));

        assertEquals(manifest, cleanManifest);
        assertEquals(manifest, originalCleanManifest);
    }

    private Manifest readManifest(Path file) throws IOException {
        JarFile jarFile = new JarFile(file.toFile());

        Manifest manifest = jarFile.getManifest();

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
}
