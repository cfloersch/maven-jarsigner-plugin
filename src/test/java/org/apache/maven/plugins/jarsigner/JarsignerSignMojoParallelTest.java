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
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;
import org.apache.maven.jarsigner.JarSigner;
import org.apache.maven.jarsigner.JarSignerSignRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import static org.apache.maven.plugins.jarsigner.TestJavaToolResults.RESULT_ERROR;
import static org.apache.maven.plugins.jarsigner.TestJavaToolResults.RESULT_OK;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.*;

public class JarsignerSignMojoParallelTest {

    private MavenProject project = mock(MavenProject.class);
    private JarSigner jarSigner = mock(JarSigner.class);
    private Path projectDir;
    private Map<String, String> configuration = new LinkedHashMap<>();
    private MojoTestCreator<JarsignerSignMojo> mojoTestCreator;
    private ExecutorService executor;
    private Log log;

    @BeforeEach
    public void setUp(@TempDir Path tempDir) throws Exception {
        assertTrue(Files.exists(tempDir));
        projectDir = tempDir;


        configuration.put("processMainArtifact", "false");
        mojoTestCreator =
                new MojoTestCreator<JarsignerSignMojo>(JarsignerSignMojo.class, project, projectDir, jarSigner);
        log = mock(Log.class);
        mojoTestCreator.setLog(log);
        executor =
                Executors.newSingleThreadExecutor(namedThreadFactory(getClass().getSimpleName()));
    }

    @AfterEach
    public void tearDown() {
        executor.shutdown();
    }

    @Test()
    @Timeout(30)
    public void test10Files2Parallel() throws Exception {
        configuration.put("archiveDirectory", createArchives(10).toString());
        configuration.put("threadCount", "2");

        // Make one jar file wait until some external event happens and let nine pass
        Semaphore semaphore = new Semaphore(9);
        when(jarSigner.execute(isA(JarSignerSignRequest.class))).then(invocation -> {
            semaphore.acquire();
            return RESULT_OK;
        });
        JarsignerSignMojo mojo = mojoTestCreator.configure(configuration);

        Future<Void> future = executor.submit(() -> {
            mojo.execute();
            return null;
        });

        // Wait until 10 invocation of execute() has happened (nine files are done and one are hanging)
        verify(jarSigner, timeout(Duration.ofSeconds(10).toMillis()).times(10)).execute(any());
        // Even though 10 invocations of execute() have happened, mojo is not yet done executing (it is waiting for one)
        assertFalse(future.isDone());

        semaphore.release(); // Release the one waiting jar file
        future.get(10, TimeUnit.SECONDS); // Wait for entire Mojo to finish
        assertTrue(future.isDone());
    }

    @Test()
    @Timeout(30)
    public void test10Files2Parallel3Hanging() throws Exception {
        configuration.put("archiveDirectory", createArchives(10).toString());
        configuration.put("threadCount", "2");

        // Make three jar files wait until some external event happens and let seven pass
        Semaphore semaphore = new Semaphore(7);
        when(jarSigner.execute(isA(JarSignerSignRequest.class))).then(invocation -> {
            semaphore.acquire();
            return RESULT_OK;
        });
        JarsignerSignMojo mojo = mojoTestCreator.configure(configuration);

        Future<Void> future = executor.submit(() -> {
            mojo.execute();
            return null;
        });

        // Wait until 9 invocations to execute has happened (2 is ongoing and 1 has not yet happened)
        verify(jarSigner, timeout(Duration.ofSeconds(10).toMillis()).times(9)).execute(any());
        assertFalse(future.isDone());

        semaphore.release(); // Release one waiting jar file

        // Wait until 10 invocation to execute has happened (8 are done and 2 are hanging)
        verify(jarSigner, timeout(Duration.ofSeconds(10).toMillis()).times(10)).execute(any());

        semaphore.release(2); // Release last two jar files
        future.get(10, TimeUnit.SECONDS); // Wait for entire Mojo to finish
        assertTrue(future.isDone());
    }

    @Test()
    @Timeout(30)
    public void test10Files1Parallel() throws Exception {
        configuration.put("archiveDirectory", createArchives(10).toString());
        configuration.put("threadCount", "1");

        // Make one jar file wait until some external event happens and let nine pass
        Semaphore semaphore = new Semaphore(9);
        when(jarSigner.execute(isA(JarSignerSignRequest.class))).then(invocation -> {
            semaphore.acquire();
            return RESULT_OK;
        });
        JarsignerSignMojo mojo = mojoTestCreator.configure(configuration);

        Future<Void> future = executor.submit(() -> {
            mojo.execute();
            return null;
        });

        // Wait until 10 invocation to execute has happened (nine has finished and one is hanging).
        verify(jarSigner, timeout(Duration.ofSeconds(10).toMillis()).times(10)).execute(any());
        assertFalse(future.isDone());

        semaphore.release(); // Release the one waiting jar file
        future.get(10, TimeUnit.SECONDS); // Wait for entire Mojo to finish
        assertTrue(future.isDone());
    }

    @Test()
    @Timeout(30)
    public void test10Files2ParallelOneFail() throws Exception {
        configuration.put("archiveDirectory", createArchives(10).toString());
        configuration.put("threadCount", "2");

        when(jarSigner.execute(isA(JarSignerSignRequest.class)))
                .thenReturn(RESULT_OK)
                .thenReturn(RESULT_OK)
                .thenReturn(RESULT_ERROR)
                .thenReturn(RESULT_OK);
        JarsignerSignMojo mojo = mojoTestCreator.configure(configuration);

        MojoExecutionException mojoException = assertThrows(MojoExecutionException.class, () -> {
            mojo.execute();
        });

        assertThat(mojoException.getMessage(), containsString(String.valueOf("Failed executing 'jarsigner ")));
    }

    @Test
    public void testInvalidThreadCount() throws Exception {
        Artifact mainArtifact = TestArtifacts.createJarArtifact(projectDir, "my-project.jar");
        when(project.getArtifact()).thenReturn(mainArtifact);
        when(jarSigner.execute(any(JarSignerSignRequest.class))).thenReturn(RESULT_OK);
        configuration.put("processMainArtifact", "true");
        configuration.put("threadCount", "0"); // Setting an "invalid" value
        JarsignerSignMojo mojo = mojoTestCreator.configure(configuration);

        mojo.execute();

        verify(jarSigner, times(1)).execute(any());
        verify(log).warn(contains("Invalid threadCount value"));
        verify(log).warn(contains("Was '0'"));
    }

    private Path createArchives(int numberOfArchives) throws IOException {
        Path archiveDirectory = projectDir.resolve("my_archive_dir");
        Files.createDirectories(archiveDirectory);
        for (int i = 0; i < numberOfArchives; i++) {
            Path file = archiveDirectory.resolve("archive" + i + ".jar");
            TestArtifacts.createDummyZipFile(file);
        }
        return archiveDirectory;
    }

    private static ThreadFactory namedThreadFactory(String threadNamePrefix) {
        return r -> new Thread(r, threadNamePrefix + "-Thread");
    }
}
