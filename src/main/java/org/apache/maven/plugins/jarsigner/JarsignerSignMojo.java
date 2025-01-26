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

import javax.inject.Inject;
import javax.inject.Named;

import java.io.File;
import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;

import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.shared.utils.StringUtils;
import org.xpertss.jarsigner.Identity;
import org.xpertss.jarsigner.IdentityBuilder;
import org.xpertss.jarsigner.JarSignerUtil;
import org.apache.maven.shared.utils.cli.javatool.JavaToolException;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcher;

/**
 * Signs a project artifact and attachments using jarsigner.
 */
@Mojo(name = "sign", defaultPhase = LifecyclePhase.PACKAGE, threadSafe = true, requiresDependencyResolution = ResolutionScope.COMPILE_PLUS_RUNTIME)
public class JarsignerSignMojo extends AbstractJarsignerMojo {


    /**
     * See <a href="https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    @Parameter(property = "jarsigner.alias")
    private String alias;

    /**
     * POJO containing keystore configuration
     */
    @Parameter
    private KeyStoreSpec keystore;


    /**
     * Trusted certificates store. Must be a JKS KeyStore
     */
    private File truststore;


    /**
     * Location of the extra certificate chain file. See
     * <a href="https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    @Parameter(property = "jarsigner.certchain", required = false)
    private File certchain;


    /**
     * See <a href="https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    @Parameter(property = "jarsigner.keypass")
    private String keypass;


    /**
     * See <a href="https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    @Parameter(property = "jarsigner.strict", defaultValue = "false")
    private boolean strict;



    /**
     * See <a href="https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    @Parameter(property = "jarsigner.sigfile")
    private String sigfile;

    /**
     * POJO to optionally specify the signature algorithm and provider
     */
    @Parameter
    private AlgorithmSpec signature;

    /**
     * POJO to optionally specify the digest algorithm and provider
     */
    @Parameter
    private AlgorithmSpec digest;

    /**
     * POJO to optionally specify time stamping authority details
     */
    @Parameter
    private TsaSpec tsa;    // TODO Figure out how to do an array of (maybe)



    /**
     * Indicates whether existing signatures should be removed from the processed JAR files prior
     * to signing them. If enabled, the resulting JAR will appear as being signed only once.
     */
    @Parameter(property = "jarsigner.removeExistingSignatures", defaultValue = "false")
    private boolean removeExistingSignatures;










    /**
     * How many times to try to sign a jar (assuming each previous attempt is a failure). This option
     * may be desirable if any network operations are used during signing, for example using a Time
     * Stamp Authority or network based PKCS11 HSM solution for storing code signing keys.
     * <p/>
     * The default value of 1 indicates that no retries should be made.
     */
    @Parameter(property = "jarsigner.maxTries", defaultValue = "1")
    private int maxTries;

    /**
     * Maximum delay, in seconds, to wait after a failed attempt before re-trying. The delay after a
     * failed attempt follows an exponential backoff strategy, with increasing delay times.
     */
    @Parameter(property = "jarsigner.maxRetryDelaySeconds", defaultValue = "0")
    private int maxRetryDelaySeconds;

    /**
     * Maximum number of parallel threads to use when signing jar files. Increases performance when
     * signing multiple jar files, especially when network operations are used during signing, for
     * example when using a Time Stamp Authority or network based PKCS11 HSM solution for storing
     * code signing keys. Note: the logging from the signing process will be interleaved, and harder
     * to read, when using many threads.
     */
    @Parameter(property = "jarsigner.threadCount", defaultValue = "1")
    private int threadCount;





    /** Current WaitStrategy, to allow for sleeping after a signing failure. */
    private WaitStrategy waitStrategy = this::defaultWaitStrategy;

    private TsaSelector tsaSelector;

    /** Exponent limit for exponential wait after failure function. 2^20 = 1048576 sec ~= 12 days. */
    private static final int MAX_WAIT_EXPONENT_ATTEMPT = 20;



    private Identity identity;

    @Inject
    public JarsignerSignMojo(@Named("mng-4384") SecDispatcher securityDispatcher)
    {
        super(securityDispatcher);
    }

    // for testing; invoked via reflection
    JarsignerSignMojo()
    {
        super(null);
    }





    @Override
    protected void preProcessArchive(final Path archive)
        throws MojoExecutionException
    {
        if (removeExistingSignatures) {
            try {
                JarSignerUtil.unsignArchive(archive);
            } catch (IOException e) {
                throw new MojoExecutionException("Failed to unsign archive " + archive + ": " + e.getMessage(), e);
            }
        }
    }

    @Override
    protected void configure()
        throws MojoExecutionException
    {
        super.configure();

        System.out.println("Digest: " + digest);
        System.out.println("Signature: " + signature);
        System.out.println("Tsa: " + tsa);


        if (maxTries < 1) {
            getLog().warn(getMessage("invalidMaxTries", maxTries));
            maxTries = 1;
        }

        if (maxRetryDelaySeconds < 0) {
            getLog().warn(getMessage("invalidMaxRetryDelaySeconds", maxRetryDelaySeconds));
            maxRetryDelaySeconds = 0;
        }

        if (threadCount < 1) {
            getLog().warn(getMessage("invalidThreadCount", threadCount));
            threadCount = 1;
        }



        if(tsa == null) {
            tsaSelector = new TsaSelector();
        } else {
            // Why is tsa not null?
            int count = tsa.validCount();
            if (count == 0) {
                getLog().warn(getMessage("warnUsageTsaUriAndTsaCertMissing"));
            } else if (count > 1) {
                getLog().warn(getMessage("warnUsageTsaUriAndTsaCertSimultaneous"));
            }
            if (false && maxTries == 1) {
                // TODO If there are multiple TSA then we need a retry
                getLog().warn(getMessage("warnUsageMultiTsaWithoutRetry", 0));
            }
            tsaSelector = new TsaSelector();    // TODO
            //tsaSelector = new TsaSelector(tsa, tsacert, tsapolicyid, tsadigestalg);
        }


        System.out.println("Keystore: " + keystore);

        try {
            IdentityBuilder builder = new IdentityBuilder();
            builder.strict(strict).trustStore(JarSignerUtil.toPath(truststore))
               .certificatePath(JarSignerUtil.toPath(certchain))
               .alias(alias).keyPass(create(keypass));
            if(keystore != null) {
                builder.keyStore(JarSignerUtil.toPath(keystore.getPath()))
                   .storePass(create(keystore.getStorePass()));
                if(StringUtils.isEmpty(keystore.getProvider())) {
                    builder.storeType(keystore.getStoreType());
                } else {
                    builder.storeType(keystore.getStoreType(), keystore.getProvider());
                }
            }
            // TODO Impl TSA
            this.identity = builder.build();
            getLog().debug("Loaded identity: " + identity);

        } catch(Exception e) {
            throw new MojoExecutionException(e);
        }


    }


    /**
     * {@inheritDoc} Processing of files may be parallelized for increased performance.
     *
     * TODO Move this parallelization into AbstractJarsignerMojo and make it final
     * Can verify be done in parallel? Answer is yes unless the goal is to dump the
     * signing info to the log.
     */
    @Override
    protected void processArchives(List<Path> archives) throws MojoExecutionException {
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        List<Future<Void>> futures = archives.stream()
                .map(file -> executor.submit((Callable<Void>) () -> {
                    processArchive(file);
                    return null; // Return dummy value to conform with Void type
                }))
                .collect(Collectors.toList());
        try {
            for (Future<Void> future : futures) {
                future.get(); // Wait for completion. Result ignored, but may raise any Exception
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new MojoExecutionException("Thread interrupted while waiting for jarsigner to complete", e);
        } catch (ExecutionException e) {
            if (e.getCause() instanceof MojoExecutionException) {
                throw (MojoExecutionException) e.getCause();
            }
            throw new MojoExecutionException("Error processing archives", e);
        } finally {
            // Shutdown of thread pool. If an Exception occurred, remaining threads will be aborted "best effort"
            executor.shutdownNow();
        }
    }

    /**
     * {@inheritDoc}
     *
     * Will retry signing up to maxTries times if it fails.
     *
     * @throws MojoExecutionException if all signing attempts fail
     */
    protected void executeJarSigner()
            throws JavaToolException, MojoExecutionException {

        for (int attempt = 0; attempt < maxTries; attempt++) {
            // Attempt the signing process

            /*
            JavaToolResult result = jarSigner.execute(request);
            int resultCode = result.getExitCode();
            if (resultCode == 0) {
                return;
            }
            tsaSelector.registerFailure(); // Could be TSA server problem or something unrelated to TSA


            if (attempt < maxTries - 1) { // If not last attempt
                waitStrategy.waitAfterFailure(attempt, Duration.ofSeconds(maxRetryDelaySeconds));
                updateJarSignerRequestWithTsa((JarSignerSignRequest) request, tsaSelector.getServer());
            } else {
                // Last attempt failed, use this failure as resulting failure
                throw new MojoExecutionException(
                        getMessage("failure", getCommandlineInfo(result.getCommandline()), resultCode));
            }

             */
        }
    }



    /** Set current WaitStrategy. Package private for testing. */
    void setWaitStrategy(WaitStrategy waitStrategy) {
        this.waitStrategy = waitStrategy;
    }

    /** Wait/sleep after a signing failure before the next re-try should happen. */
    @FunctionalInterface
    interface WaitStrategy {
        /**
         * Will be called after a signing failure, if a re-try is about to happen. May as a side effect sleep current
         * thread for some time.
         *
         * @param attempt the attempt number (0 is the first)
         * @param maxRetryDelay the maximum duration to sleep (may be zero)
         * @throws MojoExecutionException if the sleep was interrupted
         */
        void waitAfterFailure(int attempt, Duration maxRetryDelay) throws MojoExecutionException;
    }

    private void defaultWaitStrategy(int attempt, Duration maxRetryDelay) throws MojoExecutionException {
        waitAfterFailure(attempt, maxRetryDelay, Thread::sleep);
    }

    /** Thread.sleep(long millis) interface to make testing easier */
    @FunctionalInterface
    interface Sleeper {
        void sleep(long millis) throws InterruptedException;
    }

    /** Package private for testing */
    void waitAfterFailure(int attempt, Duration maxRetryDelay, Sleeper sleeper) throws MojoExecutionException {
        // Use attempt as exponent in the exponential function, but limit it to avoid too big values.
        int exponentAttempt = Math.min(attempt, MAX_WAIT_EXPONENT_ATTEMPT);
        long delayMillis = (long) (Duration.ofSeconds(1).toMillis() * Math.pow(2, exponentAttempt));
        delayMillis = Math.min(delayMillis, maxRetryDelay.toMillis());
        if (delayMillis > 0) {
            getLog().info("Sleeping after failed attempt for " + (delayMillis / 1000) + " seconds...");
            try {
                sleeper.sleep(delayMillis);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new MojoExecutionException("Thread interrupted while waiting after failure", e);
            }
        }
    }


    KeyStore.PasswordProtection create(String passwd)
    {
        if(StringUtils.isEmpty(passwd)) return null;
        return new KeyStore.PasswordProtection(passwd.toCharArray());
    }
}
