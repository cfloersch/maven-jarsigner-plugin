package org.xpertss.crypto.pkcs_old;

import org.xpertss.crypto.asn1.ASN1Integer;
import org.xpertss.crypto.asn1.ASN1Opaque;
import org.xpertss.crypto.asn1.ASN1Sequence;
import org.xpertss.crypto.asn1.ASN1SetOf;
import org.xpertss.crypto.asn1.ASN1TaggedType;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.CertPath;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

/**
 * PKCS7 as defined in RSA Laboratories PKCS7 Technical Note. Profile Supports only
 * {@code SignedData} ContentInfo type, where the type of data signed is plain Data.
 * <p/>
 * SignedData ::= SEQUENCE {
 *    version Version,
 *    digestAlgorithms DigestAlgorithmIdentifiers,
 *    contentInfo ContentInfo,
 *    certificates [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL,
 *    crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
 *    signerInfos SignerInfos
 * }
 *
 *  Version ::= INTEGER
 *
 *  DigestAlgorithmIdentifiers ::=
 *      SET OF DigestAlgorithmIdentifier
 *
 *  ExtendedCertificateOrCertificate ::= CHOICE {
 *      certificate Certificate, -- X.509
 *      extendedCertificate [0] IMPLICIT ExtendedCertificate
 *  }
 *
 *  ExtendedCertificatesAndCertificates ::=
 *      SET OF ExtendedCertificateOrCertificate
 *
 *  CertificateRevocationLists ::=
 *      SET OF CertificateRevocationList
 *
 *  SignerInfos ::= SET OF SignerInfo
 *
 * <p/>
 * For signedData, {@code crls}, {@code attributes} and PKCS#6 Extended Certificates
 * are not supported.
 *
 * https://www.itu.int/ITU-T/formal-language/itu-t/x/x420/1999/PKCS7.html
 * https://signify.readthedocs.io/en/latest/pkcs7.html
 * https://www.rfc-editor.org/rfc/rfc2315.html
 */
public class PKCS7SignedData extends ASN1Sequence {

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



    public PKCS7SignedData()
    {
        add(new ASN1Integer());                                     // version (Generally 1)
        add(new ObjectIdentifier());                                // digestAlgorithmIdentifiers
        add(new ContentInfo());                                     // Content Info
        add(new ASN1TaggedType(0, new Certificates(), false, true));             // Implicit Certificates (Optional)
        add(new ASN1TaggedType(1,new ASN1SetOf(ASN1Opaque.class), false, true));                     // Implicit CRLs (Optional)
        add(new ASN1SetOf(SignerInfo.class));                       // Signer Infos
    }


    public PKCS7SignedData(CertPath signerChain, ContentInfo contentInfo, SignerInfo ... signers)
    {

    }




    /**
     * Returns the version number of this PKCS7 block.
     * @return the version or null if version is not specified
     *         for the content type.
     */
    public BigInteger getVersion()
    {
        return version;
    }

    /**
     * Returns the message digest algorithms specified in this PKCS7 block.
     * @return the array of Digest Algorithms or null if none are specified
     *         for the content type.
     */
    public AlgorithmId[] getDigestAlgorithmIds()
    {
        return  digestAlgorithmIds;
    }

    /**
     * Returns the content information specified in this PKCS7 block.
     */
    public ContentInfo getContentInfo()
    {
        return contentInfo;
    }

    /**
     * Returns the X.509 certificates listed in this PKCS7 block.
     * @return a clone of the array of X.509 certificates or null if
     *         none are specified for the content type.
     */
    public X509Certificate[] getCertificates()
    {
        return (certificates != null) ? certificates.clone() : null;
    }

    /**
     * Returns the X.509 crls listed in this PKCS7 block.
     * @return a clone of the array of X.509 crls or null if none
     *         are specified for the content type.
     */
    public X509CRL[] getCRLs()
    {
        return (crls != null) ? crls.clone() : null;
    }

    /**
     * Returns the signer's information specified in this PKCS7 block.
     * @return the array of Signer Infos or null if none are specified
     *         for the content type.
     */
    public SignerInfo[] getSignerInfos()
    {
        return signerInfos;
    }

    /**
     * Returns the X.509 certificate listed in this PKCS7 block
     * which has a matching serial number and Issuer name, or
     * null if one is not found.
     *
     * @param serial the serial number of the certificate to retrieve.
     * @param issuerName the Distinguished Name of the Issuer.
     */
    public X509Certificate getCertificate(BigInteger serial, X500Name issuerName)
    {
        if (certificates != null) {
            if (certIssuerNames == null)
                populateCertIssuerNames();
            for (int i = 0; i < certificates.length; i++) {
                X509Certificate cert = certificates[i];
                BigInteger thisSerial = cert.getSerialNumber();
                if (serial.equals(thisSerial)
                   && issuerName.equals(certIssuerNames[i]))
                {
                    return cert;
                }
            }
        }
        return null;
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
