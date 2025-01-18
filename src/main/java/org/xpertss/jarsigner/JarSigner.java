package org.xpertss.jarsigner;

import java.net.URI;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertPath;
import java.util.Objects;
import java.util.zip.ZipFile;

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
public class JarSigner {

    /*
       NOTES: A Jar file can be signed multiple times. For each signing a
       different signerName should be used. When that occurs there will be
       a SF and DSA/RSA/EC file prefixed with each signerName.

       I think some of the impls have a tendancy to remove previous
       signatures. Not sure if that is accurate, unless we are talking
       about cases with the same signerName.
     */

    private final PrivateKey privateKey;
    private final CertPath certPath;

    private final MessageDigest digest;
    private final Signature signature;
    private final String signerName;

    private final URI tsa;
    private final String tsaPolicyId;
    private final String tsaDigestAlgorithm;


    private JarSigner(Builder builder)
    {
        this.tsa = builder.tsa;
        this.digest = builder.digest;
        this.signature = builder.signature;
        this.certPath = builder.certPath;
        this.privateKey = builder.privateKey;
        this.signerName = builder.signerName;
        this.tsaPolicyId = builder.tsaPolicyId;
        this.tsaDigestAlgorithm = builder.tsaDigestAlgorithm;
    }

    public String getDigestAlgorithm()
    {
        return digest.getAlgorithm();
    }

    public String getSignatureAlgorithm()
    {
        return signature.getAlgorithm();
    }

    public String getSignerName()
    {
        return signerName;
    }

    public URI getTsa()
    {
        return tsa;
    }


    // TODO Maybe use a Path instead of an Output Stream?
    // Eliminates the need to indicate anything about the output stream state in failure cases
    public void sign(ZipFile file, Path output)
    {
        // default impl does not close ZipFile
    }


    public static class Builder {

        private final PrivateKey privateKey;
        private final CertPath certPath;

        private MessageDigest digest;
        private Signature signature;
        private String signerName;

        private URI tsa;
        private String tsaPolicyId;
        private String tsaDigestAlgorithm;

        public Builder(Identity identity)
        {
            this.signerName = identity.getName();
            this.privateKey = identity.getPrivateKey();
            this.certPath = identity.getCertificatePath();
        }

        public Builder(PrivateKey privateKey, CertPath certPath)
        {
            this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
            this.certPath = Objects.requireNonNull(certPath, "certPath");
        }

        public Builder digestAlgorithm(String algorithm)
            throws NoSuchAlgorithmException
        {
            /*
              Apparently, the signature file (*.SF) includes hash of the manifest file/manifest
              header and one line for each file in the JAR with filename, digestAlgName, and
              digest. It does not actually contain a signature.

              The entire SF file is then run through a Signature alg, the resulting signature
              written to a file with a .DSA or .RSA or .EC extension. This signature block file
              also includes the certificate chain of the key used to generate the signature. I
              suspect that the signature itself identifies the full algorithm (to include the
              digest used).

              So we can use a simple digest for the SF file contents and then sign that whole
              SF with a better alg like SHA-256 as an example.
             */
            digest = MessageDigest.getInstance(algorithm);
            return this;
        }

        public Builder digestAlgorithm(String algorithm, Provider provider)
            throws NoSuchAlgorithmException
        {
            digest = MessageDigest.getInstance(algorithm, provider);
            return this;
        }

        // TODO I would love to know what the difference is between Signature (which includes a digest alg)
        // and the explicit digestAlgorithm defined above? In what world are they different?
        public Builder signatureAlgorithm(String algorithm)
            throws NoSuchAlgorithmException
        {
            signature = Signature.getInstance(algorithm);
            return this;
        }

        public Builder signatureAlgorithm(String algorithm, Provider provider)
            throws NoSuchAlgorithmException
        {
            signature = Signature.getInstance(algorithm, provider);
            return this;
        }

        public Builder tsa(URI uri)
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
            this.tsa = uri;
            return this;
        }

        /**
         * The digest algorithm to use for the timestamping request.
         * <p/>
         * The default value is the same as the result of {@link #getDigestAlgorithm()}
         *
         * @param tsaDigestAlgorithm
         * @return
         */
        public Builder tsaDigestAlgorithm(String tsaDigestAlgorithm)
        {
            // jarsinger supports a tsacert alias. Not sure what it does or if we should also include it
            // apparently the tsacert alias looks up a certifiate in the Keystore with the given alias. It
            // then extracts the Subject Information Access to obtain the tsa URL. It makes no sense to
            // define both tsa and tsacert. It's really one or the other.
            this.tsaDigestAlgorithm = tsaDigestAlgorithm;
            return this;
        }

        /**
         * TSAPolicyID for Timestamping Authority. No default value.
         *
         * @param tsaPolicyId
         * @return
         */
        public Builder tsaPolicyId(String tsaPolicyId)
        {
            /*
               Specifies the object identifier (OID) that identifies the policy ID to be
               sent to the TSA server. If this option is not specified, no policy ID is
               sent and the TSA server will choose a default policy ID.

               Object identifiers are defined by X.696, which is an ITU Telecommunication
               Standardization Sector (ITU-T) standard. These identifiers are typically
               period-separated sets of non-negative digits like 1.2.3.4, for example.
             */
            this.tsaPolicyId = tsaPolicyId;
            return this;
        }


        /**
         * Sets the signer name. The name will be used as the base name for the signature
         * files. All lowercase characters will be converted to uppercase for signature
         * file names. If a signer name is not specified, the string "SIGNER" will be
         * used.
         *
         * @param name The signer name
         * @return this builder
         */
        public Builder signerName(String name)
        {
            // If no -sigfile option appears on the command line, then the base file name
            // for the .SF and .DSA files is the first 8 characters of the alias name
            // specified on the command line, all converted to uppercase. If the alias name
            // has fewer than 8 characters, then the full alias name is used. If the alias
            // name contains any characters that are not allowed in a signature file name,
            // then each such character is converted to an underscore (_) character in
            // forming the file name. Valid characters include letters, digits, underscores,
            // and hyphens.


            // Looks like Sun's impl always truncates this to 8 characters and makes it
            // Upper Case. Also a signerName must be a-zA-Z0-9-_ Everything else is
            // converted to underscores. Jarsigner converts aliases and errors on explicit
            // arguments.
            this.signerName = signerName;
            return this;
        }

        public JarSigner build()
        {
            return null;
        }

        private Signature deriveDefaultSignature()
        {
            /*
               If the signer's public and private keys are DSA keys, then jarsigner signs
               the JAR file with the SHA1withDSA algorithm. If the signer's keys are RSA
               keys, then jarsigner attempts to sign the JAR file with the SHA256withRSA
               algorithm. If the signer's keys are EC keys, then jarsigner signs the JAR
               file with the SHA256withECDSA algorithm.
             */
            if("RSA".equalsIgnoreCase(privateKey.getAlgorithm())) {

            } else if("EC".equalsIgnoreCase(privateKey.getAlgorithm())) {

            } else if("DSA".equalsIgnoreCase(privateKey.getAlgorithm())) {

            }
            throw new IllegalArgumentException("Cannot derive ambiguous signature");
        }
    }

}
