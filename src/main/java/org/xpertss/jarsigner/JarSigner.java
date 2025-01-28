package org.xpertss.jarsigner;

import java.net.URI;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertPath;
import java.util.Locale;
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

    private final TsaSigner tsa;


    private JarSigner(Builder builder)
    {
        this.privateKey = builder.privateKey;
        this.certPath = builder.certPath;

        this.tsa = builder.tsa;
        this.digest = builder.digest;
        this.signature = builder.signature;
        this.signerName = builder.signerName;
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
        return tsa.getUri();
    }


    // TODO Maybe use a Path instead of an Output Stream?
    // TODO Maybe use Path instead of ZipFile?
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
        private String signerName = "SIGNER";

        private TsaSigner tsa;

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
            digest = MessageDigest.getInstance(algorithm);
            return this;
        }

        public Builder digestAlgorithm(String algorithm, Provider provider)
            throws NoSuchAlgorithmException
        {
            digest = MessageDigest.getInstance(algorithm, provider);
            return this;
        }


        public Builder signatureAlgorithm(String algorithm)
            throws NoSuchAlgorithmException, IllegalArgumentException
        {
            signature = Signature.getInstance(algorithm);
            
            return this;
        }

        public Builder signatureAlgorithm(String algorithm, Provider provider)
            throws NoSuchAlgorithmException, IllegalArgumentException
        {
            signature = Signature.getInstance(algorithm, provider);
            return this;
        }



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

            for (int j = 0; j < name.length(); j++) {
                char c = name.charAt(j);
                if (!
                   ((c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') ||
                      (c == '-') ||
                      (c == '_'))) {
                    throw new IllegalArgumentException(
                       "Invalid characters in name");
                }
            }
            this.signerName = name;
            return this;
        }


        public JarSigner build()
           throws NoSuchAlgorithmException
        {
            if(digest == null) {
                digest = MessageDigest.getInstance("SHA-256");
            }
            if(signature == null) {
                String keyalg = privateKey.getAlgorithm();
                String sigalg = defaultSignatureForKey(keyalg);
                signature = Signature.getInstance(sigalg);
            }
            return new JarSigner(this);
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
