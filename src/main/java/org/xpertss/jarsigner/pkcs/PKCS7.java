package org.xpertss.jarsigner.pkcs;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertPath;

/**
 * PKCS7 as defined in RSA Laboratories PKCS7 Technical Note. Profile Supports only
 * {@code SignedData} ContentInfo type, where to the type of data signed is plain
 * Data.
 * <p/>
 * For signedData, {@code crls}, {@code attributes} and PKCS#6 Extended Certificates
 * are not supported.
 */
public class PKCS7 {

    /*
        https://datatracker.ietf.org/doc/draft-ietf-cose-cbor-encoded-cert/06/

        RSASSA-PKCS1-v1_5 with SHA-1                1.2.840.113549.1.1.5
        RSASSA-PKCS1-v1_5 with SHA-256              1.2.840.113549.1.1.11
        RSASSA-PKCS1-v1_5 with SHA-384              1.2.840.113549.1.1.12
        RSASSA-PKCS1-v1_5 with SHA-512              1.2.840.113549.1.1.13

        RSASSA-PSS with SHA-256                     1.2.840.113549.1.1.10
        RSASSA-PSS with SHA-384                     1.2.840.113549.1.1.10
        RSASSA-PSS with SHA-512                     1.2.840.113549.1.1.10

        ECDSA with SHA-1                            1.2.840.10045.4.1
        ECDSA with SHA-256                          1.2.840.10045.4.3.2
        ECDSA with SHA-384                          1.2.840.10045.4.3.3
        ECDSA with SHA-512                          1.2.840.10045.4.3.4

        Ed25519                                     1.3.101.112
        Ed448                                       1.3.101.113
     */


    /*
        Algorithm OID map
        https://github.com/JetBrains/jdk8u_jdk/blob/master/src/share/classes/sun/security/x509/AlgorithmId.java#L651
     */


    /*
     * Object identifier for the timestamping key purpose.
     */
    private static final String KP_TIMESTAMPING_OID = "1.3.6.1.5.5.7.3.8";

    /*
     * Object identifier for extendedKeyUsage extension
     */
    private static final String EXTENDED_KEY_USAGE_OID = "2.5.29.37";

    public PKCS7(CertPath signerChain, ContentInfo contentInfo, SignerInfo ... signers)
    {

    }

    public byte[] getEncoded()
    {
        //https://github.com/JetBrains/jdk8u_jdk/blob/master/src/share/classes/sun/security/pkcs/PKCS7.java#L494
        return new byte[0];
    }


    private void parse(InputStream derin)
        throws IOException
    {
        // https://github.com/JetBrains/jdk8u_jdk/blob/master/src/share/classes/sun/security/pkcs/PKCS7.java#L270
    }

}
