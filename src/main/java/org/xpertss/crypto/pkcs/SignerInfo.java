package org.xpertss.crypto.pkcs;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * A SignerInfo, as defined in PKCS#7's signedData type.
 *
 * https://github.com/JetBrains/jdk8u_jdk/blob/master/src/share/classes/sun/security/pkcs/SignerInfo.java
 */
public class SignerInfo {

    private  BigInteger version = BigInteger.ONE;

    private X500Principal issuer;
    private BigInteger serialNumber;
    private byte[] signature;
    private String signatureAlg;
    private PKCS9Attributes unauthenticated;

    public SignerInfo(X500Principal issuer, BigInteger serialNumber, byte[] signature, String signatureAlg, PKCS9Attributes unauthenticated)
    {
        this.issuer = issuer;
        this.serialNumber = serialNumber;
        this.signature = signature;
        this.signatureAlg = signatureAlg;
        this.unauthenticated = unauthenticated;
    }


    public void encodeTo(OutputStream out)
        throws IOException
    {
    }


    public static SignerInfo create(CertPath signerChain, byte[] signature, String signatureAlg, PKCS9Attributes unauthenticated)
    {
        List<? extends Certificate> certs = signerChain.getCertificates();
        X509Certificate signer = (X509Certificate) certs.get(0);
        X500Principal issuer = signer.getIssuerX500Principal();
        BigInteger serialNumber = signer.getSerialNumber();
        return new SignerInfo(issuer, serialNumber, signature, signatureAlg, unauthenticated);
    }

}
