package org.xpertss.jarsigner.plugins;

import javax.inject.Inject;
import javax.inject.Named;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;
import java.util.zip.ZipFile;

import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.shared.utils.StringUtils;
import org.xpertss.jarsigner.Identity;
import org.xpertss.jarsigner.IdentityBuilder;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcher;
import org.xpertss.jarsigner.JarSigner;
import org.xpertss.jarsigner.TsaSigner;
import org.xpertss.jarsigner.jar.ArchiveUtils;

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
    @Parameter
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
    private TsaSpec tsa;



    /**
     * Indicates whether existing signatures should be removed from the processed JAR files
     * prior to signing them. If enabled, the resulting JAR will appear as being signed only
     * once.
     */
    @Parameter(property = "jarsigner.clean", defaultValue = "false")
    private boolean clean;







    /**
     * Maximum number of parallel threads to use when signing jar files. Increases performance
     * when signing multiple jar files, especially when network operations are used during
     * signing, for example when using a Time Stamp Authority or network based PKCS11 HSM
     * solution for storing code signing keys. Note: the logging from the signing process
     * will be interleaved, and harder to read, when using many threads.
     */
    @Parameter(property = "jarsigner.threadCount", defaultValue = "1")
    private int threadCount;







    private JarSigner.Builder signerBuilder;

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
    protected void configure()
        throws MojoExecutionException
    {
        super.configure();

        if (threadCount < 1) {
            getLog().warn(getMessage("invalidThreadCount", threadCount));
            threadCount = 1;
        }

        getLog().debug("Keystore: " + keystore);

        try {
            IdentityBuilder builder = new IdentityBuilder();
            builder.strict(strict)
                    .trustStore(toPath(truststore))
                    .certificatePath(toPath(certchain))
                    .alias(alias).keyPass(create(keypass));
            if(keystore != null) {
                builder.keyStore(toPath(keystore.getPath()))
                   .storePass(create(keystore.getStorePass()))
                   .storeType(keystore.getStoreType(), keystore.getProvider());
            }
            Identity identity = builder.build();
            getLog().debug("Loaded identity: " + identity);

            TsaSigner tsaSigner = null;
            if(tsa != null) {
                tsaSigner = tsa.build();
                getLog().debug("Loaded timestamp authority: " + tsaSigner);
            }

            if(StringUtils.isEmpty(sigfile)) {
                sigfile = ArchiveUtils.cleanSigFileName(identity.getName());
            }
            if(digest == null) digest = new AlgorithmSpec();
            if(signature == null) signature = new AlgorithmSpec();

            signerBuilder = new JarSigner.Builder(identity)
                                    .digestAlgorithm(digest.getAlgorithm(), digest.getProvider())
                                    .signatureAlgorithm(signature.getAlgorithm(), signature.getProvider())
                                    .signerName(sigfile).tsa(tsaSigner).clean(clean);

        } catch(Exception e) {
            throw new MojoExecutionException(e);
        }


    }



    /**
     * {@inheritDoc} Processing of files may be parallelized for increased performance.
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

    @Override
    protected void processArchive(Path archive)
        throws MojoExecutionException
    {
        if(archive == null) throw new NullPointerException("archive");
        getLog().info(getMessage("processing", archive));
        try {
            Path output = archive.resolveSibling(archive.getFileName() + ".sig");
            try(ZipFile zipFile = new ZipFile(archive.toFile())) {
                JarSigner signer = signerBuilder.build();
                signer.sign(zipFile, output);
            }
            Files.move(output, archive, StandardCopyOption.REPLACE_EXISTING);
        } catch(Exception e) {
            throw new MojoExecutionException(e);
        }
    }



    KeyStore.PasswordProtection create(String passwd)
        throws MojoExecutionException
    {
        if(StringUtils.isEmpty(passwd)) return null;
        return new KeyStore.PasswordProtection(decrypt(passwd).toCharArray());
    }

    Path toPath(File file)
    {
        return (file != null) ? file.toPath() : null;
    }

}
