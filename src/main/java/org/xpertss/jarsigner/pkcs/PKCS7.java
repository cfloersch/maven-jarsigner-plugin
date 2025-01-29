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
        return null;
    }


    private void parse(InputStream derin)
        throws IOException
    {
        // https://github.com/JetBrains/jdk8u_jdk/blob/master/src/share/classes/sun/security/pkcs/PKCS7.java#L270
    }

}
