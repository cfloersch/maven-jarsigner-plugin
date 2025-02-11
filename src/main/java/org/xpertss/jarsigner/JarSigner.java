package org.xpertss.jarsigner;

import org.apache.maven.shared.utils.StringUtils;
import org.xpertss.jarsigner.jar.*;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.jar.JarFile;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/*
   Usage: An external system will parse all of the options around keys and obtain
   a key and a cert chain. For verification we may need to have another impl or
   provide a means to init with CertChain but not PrivateKey.

   Once the key/certs are loaded we can create an instance of the builder. On
   to that builder we specify the various parts based on the user's options.
   For example Signature Alg, Digest Alg, etc. Both of which supply the Provider
   that was specified if one was specified. That would be used to load KeyStore
   as well.

   The default tool attempts to determine if storepass/keystore properties should
   be specified before attempting to load the KeyStore. I say if we have the
   properties we use them otherwise, we simply attempt without them. PKCS#11 and
   KMS KeyStores usually do not require either.

   In the maven context there is no prompting so we won't impl any of that.

   The jarsigner uses the specified signedJar as output unless it equals the
   input jar where it errors. If no signedjar is specified it simply appends
   the extension .sig
 */

/**
 * A JarSigner instance that signs a given Java Archive (JAR) with the given
 * identity information.
 * <p/>
 * A JarSigner instance is NOT thread safe.
 */
public final class JarSigner {

    /*
       NOTES: A Jar file can be signed multiple times. For each signing a
       different signerName should be used. When that occurs there will be
       a SF and DSA/RSA/EC file prefixed with each signerName.
     */

    private final PrivateKey privateKey;
    private final X509Certificate[] chain;

    private final MessageDigest digest;
    private final Signature signature;
    private final String signerName;

    private final TsaSigner tsa;
    private final boolean clean;


    private JarSigner(Builder builder, MessageDigest digest, Signature signature)
    {
        this.privateKey = builder.privateKey;
        this.chain = builder.chain;
        this.digest = digest;
        this.signature = signature;

        this.tsa = builder.tsa;
        this.signerName = builder.signerName;
        this.clean = builder.clean;
    }

    /**
     * Returns the digest algorithm this JarSigner is configured to
     * use.
     */
    public String getDigestAlgorithm()
    {
        return digest.getAlgorithm();
    }

    /**
     * Returns the signature algorithm this JarSigner is configured
     * to use.
     */
    public String getSignatureAlgorithm()
    {
        return signature.getAlgorithm();
    }

    /**
     * Returns the signer name this JarSigner is configured to use.
     */
    public String getSignerName()
    {
        return signerName;
    }

    /**
     * Returns the URI of the Time Stamp Authority this JarSigner is
     * configured to use or {@code null} if it is not configured to
     * do time stamping.
     */
    public URI getTsa()
    {
        return tsa.getUri();
    }

    /**
     * Returns {@code true} if this JarSigner is configured to clean
     * existing signatures and digests from the output java archive.
     */
    public boolean willClean()
    {
        return clean;
    }




    /**
     * Sign the given Java Archive utilizing the specified output Path as the
     * temporary signed archive file.
     *
     * @param file The input archive to sign
     * @param output The output path to write the signed archive contents to
     * @throws IOException If an IO error occurs
     * @throws InvalidKeyException
     *      If the key returned by the identity doesn't match the signature algorithm
     * @throws SignatureException if an error occurs generating the signature
     */
    public void sign(ZipFile file, Path output)
       throws IOException, InvalidKeyException, SignatureException, NoSuchAlgorithmException
    {
        JavaArchive archive = JavaArchive.from(file, clean);
        SignatureFile sigfile = archive.generateSignatureFile(signerName, digest);

        signature.initSign(privateKey);
        SignatureBlock sigblock = sigfile.generateBlock(signature, tsa, chain);

        Manifest manifest = archive.getManifest();
        boolean modified = manifest.isModified();
        try(ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(output, StandardOpenOption.CREATE_NEW))) {
            out.putNextEntry(new ZipEntry(JarFile.MANIFEST_NAME));
            manifest.writeTo(out);

            out.putNextEntry(new ZipEntry(sigfile.getMetaName()));
            sigfile.writeTo(out);

            out.putNextEntry(new ZipEntry(sigblock.getMetaName()));
            sigblock.writeTo(out);

            if(!modified) {
                // Write out each pre-existing signature file/block
                //  If they have different names than sinerName
                String PREFIX = String.format("META-INF/%s.", signerName);

                Set<ZipEntry> signatures = archive.signatures()
                                                .filter(ze -> !ze.getName().startsWith(PREFIX))
                                                .collect(Collectors.toSet());
                for(ZipEntry ze : signatures) {
                    out.putNextEntry(ze);
                    try (InputStream in = archive.getInputStream(ze)) {
                        ArchiveUtils.copy(in, out);
                    }
                }
            } else if(archive.signatureCount() > 0) {
                // Log the fact that we are discarding signatures
                // They are discarded because modifying the manifest renders them invalid
            }

            Set<ZipEntry> entries = archive.entries().collect(Collectors.toSet());
            for(ZipEntry ze : entries) {
                out.putNextEntry(ze);
                try(InputStream in = archive.getInputStream(ze)) {
                    ArchiveUtils.copy(in, out);
                }
            }

        }

    }




    /**
     * Utility class to facilitate the creation of a JarSigner.
     */
    public static class Builder {

        private final PrivateKey privateKey;
        private final X509Certificate[] chain;

        private String digestAlg;
        private String digestProv;
        private String signatureAlg;
        private String signatureProv;

        private String signerName = "SIGNER";

        private boolean clean;

        private TsaSigner tsa;

        /**
         * Construct an instance of JarSigner Builder with the given Identity.
         * <p/>
         * The private key and cert path can be obtained from the Identity.
         */
        public Builder(Identity identity)
        {
            this.signerName = identity.getName();
            this.privateKey = identity.getPrivateKey();
            this.chain = identity.getCertificateChain();
        }

        /**
         * Alternative method to construct an instance of JarSigner Builder using
         * the privateKey and certificate chain directly.
         */
        public Builder(PrivateKey privateKey, X509Certificate ... chain)
        {
            this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
            this.chain = Objects.requireNonNull(chain, "chain");
        }

        /**
         * Configure the digest algorithm to use when computing hashes in the
         * manifest and signature file. By default the JarSigner will use SHA-256
         *
         * @param algorithm The name of the Digest algorithm to use.
         * @return the {@code JarSigner.Builder} itself.
         * @throws NoSuchAlgorithmException
         *      If the specified digest algorithm does not exist in the system
         */
        public Builder digestAlgorithm(String algorithm)
            throws NoSuchAlgorithmException
        {
            this.digestAlg = algorithm;
            if(algorithm != null) {
                MessageDigest.getInstance(algorithm);
            }
            return this;
        }

        /**
         * Configure the digest algorithm to use when computing hashes in the
         * manifest and signature file. By default the JarSigner will use SHA-256
         *
         * @param algorithm The name of the Digest algorithm to use.
         * @param provider The provider to load the named digest from
         * @return the {@code JarSigner.Builder} itself.
         * @throws NoSuchAlgorithmException
         *      If the specified digest algorithm does not exist in the provider
         */
        public Builder digestAlgorithm(String algorithm, String provider)
            throws NoSuchAlgorithmException, NoSuchProviderException
        {
            this.digestAlg = algorithm;
            this.digestProv = provider;
            if(algorithm != null) {
                if(provider != null) {
                    MessageDigest.getInstance(algorithm, provider);
                } else {
                    MessageDigest.getInstance(algorithm);
                }
            }
            return this;
        }


        /**
         * Specify the Signature algorithm to use when creating a signature block.
         * There is a default algorithm for each key type in which that signing
         * algorithm is paired with SHA-256.
         * <p/>
         * It is important to note that the verification system can only utilize
         * a specific set of algorithms.
         *
         * @param algorithm The signature algorithm to use.
         * @return the {@code JarSigner.Builder} itself.
         * @throws NoSuchAlgorithmException
         *      If the algorithm does not exist in the system
         */
        public Builder signatureAlgorithm(String algorithm)
            throws NoSuchAlgorithmException
        {
            this.signatureAlg = algorithm;
            if(algorithm != null)
                Signature.getInstance(algorithm);
            return this;
        }

        /**
         * Specify the Signature algorithm to use when creating a signature block.
         * There is a default algorithm for each key type in which that signing
         * algorithm is paired with SHA-256.
         * <p/>
         * It is important to note that the verification system can only utilize
         * a specific set of algorithms.
         *
         * @param algorithm The signature algorithm to use.
         * @param provider The provider to load the named signature from
         * @return the {@code JarSigner.Builder} itself.
         * @throws NoSuchAlgorithmException
         *      If the algorithm does not exist in the provider
         */
        public Builder signatureAlgorithm(String algorithm, String provider)
            throws NoSuchAlgorithmException, NoSuchProviderException
        {
            this.signatureAlg = algorithm;
            this.signatureProv = provider;
            if(algorithm != null) {
                if(provider != null) {
                    Signature.getInstance(algorithm, provider);
                } else {
                    Signature.getInstance(algorithm);
                }
            }
            return this;
        }



        /**
         * Indicate whether you would like all existing signatures and digests to
         * be removed prior to signing with the defined set of algorithms and
         * identity.
         * <p/>
         * By default an attempt to retain existing signatures is made. However,
         * if the existing manifest must be modified as part of this signing then
         * existing signatures will become invalid and will be removed anyway.
         *
         * @param clean True if you'd like to purge existing signatures
         * @return the {@code JarSigner.Builder} itself.
         */
        public Builder clean(boolean clean)
        {
            this.clean = clean;
            return this;
        }


        /**
         * Indicate the desired Time Stamp Authority to use when signing. By default
         * no time stamp authority is used.
         * <p/>
         * Note that TSA are remote executions and will require internet access and
         * an available provider. These network calls utilize standard Java HTTP
         * and HTTPS implementations and can have proxy, timeout, and other settings
         * defined as per standard Java definitions.
         *
         * @param tsa The Time Stamp Authority to use when signing.
         * @return the {@code JarSigner.Builder} itself.
         */
        public Builder tsa(TsaSigner tsa)
        {
            /*
               If -tsa http://example.tsa.url appears on the command line when signing
               a JAR file then a time stamp is generated for the signature. The URL,
               http://example.tsa.url, identifies the location of the Time Stamping
               Authority (TSA) and overrides any URL found with the -tsacert option.
               The -tsa option does not require the TSA public key certificate to be
               present in the keystore.

               To generate the time stamp, jarsigner communicates with the TSA with
               the Time-Stamp Protocol (TSP) defined in RFC 3161. When successful,
               the time stamp token returned by the TSA is stored with the signature
               in the signature block file.
             */
            this.tsa = tsa;
            return this;
        }




        /**
         * Sets the signer name. The name will be used as the base name for the signature
         * files. All lowercase characters will be converted to uppercase for signature
         * file names. If a signer name is not specified, the string "SIGNER" will be
         * used.
         * <p/>
         * If a signature with the given signer name already exists in the archive it
         * will be replaced.
         *
         * @param name the signer name.
         * @return the {@code JarSigner.Builder} itself.
         * @throws IllegalArgumentException if {@code name} is empty or has
         *      a size bigger than 8, or it contains characters not from the
         *      set "a-zA-Z0-9_-".
         */
        public Builder signerName(String name)
        {
            if (name.isEmpty() || name.length() > 8) {
                throw new IllegalArgumentException("Name too long");
            }

            name = name.toUpperCase(Locale.ENGLISH);

            if(!Pattern.matches("^[a-zA-Z0-9_-]*$", name)) {
                throw new IllegalArgumentException(
                        "Invalid characters in name");
            }
            this.signerName = name;
            return this;
        }


        /**
         * Constructs and returns an instance of JarSigner with the given properties.
         * <p/>
         * Will throw IllegalStateException if signer name has not been specified.
         * <p/>
         * This will utilize default SHA-256 digest algorithm if none was specified.
         * <p/>
         * This will use the appropriate variant of signature for the given identity's
         * private key and using SHA-256 digest if not explicitly specified. Ex:
         * {@code SHA256withRSA} if the identity's private key is type RSA.
         *
         * @throws IllegalStateException if the signer name has not been defined
         * @throws NoSuchAlgorithmException if the default digest or signature algorithm
         *      cannot be found, usually due to an issue with the JCE config
         * @throws NoSuchProviderException should never be thrown as it would normally
         *      be caught in the setter methods.
         */
        public JarSigner build()
            throws NoSuchAlgorithmException, NoSuchProviderException
        {
            if(StringUtils.isEmpty(signerName))
                throw new IllegalStateException("signer name not defined");

            MessageDigest digest = null;
            if(StringUtils.isEmpty(digestAlg)) {
                digest = MessageDigest.getInstance("SHA-256");
            } else if(StringUtils.isEmpty(digestProv)) {
                digest = MessageDigest.getInstance(digestAlg);
            } else {
                digest = MessageDigest.getInstance(digestAlg, digestProv);
            }

            Signature signature = null;
            if(StringUtils.isEmpty(signatureAlg)) {
                String keyalg = privateKey.getAlgorithm();
                String sigalg = defaultSignatureForKey(keyalg);
                signature = Signature.getInstance(sigalg);
            } else if(StringUtils.isEmpty(digestProv)) {
                signature = Signature.getInstance(signatureAlg);
            } else {
                signature = Signature.getInstance(signatureAlg, signatureProv);
            }

            return new JarSigner(this, digest, signature);
        }


    }



    private static String defaultSignatureForKey(String keyAlgorithm)
    {
        switch(keyAlgorithm.toUpperCase(Locale.ENGLISH)) {
            case "RSA":
                return "SHA256withRSA";
            case "EC":
                return "SHA256withECDSA";
            case "DSA":
                return "SHA256withDSA";
        }
        throw new IllegalArgumentException("Cannot derive ambiguous signature");
    }
}
