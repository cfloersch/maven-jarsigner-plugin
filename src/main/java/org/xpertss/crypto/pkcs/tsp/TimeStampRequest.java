package org.xpertss.crypto.pkcs.tsp;

import org.xpertss.crypto.asn1.*;
import org.xpertss.crypto.pkcs.AlgorithmIdentifier;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Extension;

/**
 * This class provides a timestamp request, as defined in
 * <a href="http://www.ietf.org/rfc/rfc3161.txt">RFC 3161</a>.
 * <p/>
 * The TimeStampReq ASN.1 type has the following definition:
 * <pre>
 *
 *     TimeStampReq ::= SEQUENCE {
 *         version           INTEGER { v1(1) },
 *         messageImprint    MessageImprint
 *           -- a hash algorithm OID and the hash value of the data to be
 *           -- time-stamped.
 *         reqPolicy         TSAPolicyId    OPTIONAL,
 *         nonce             INTEGER        OPTIONAL,
 *         certReq           BOOLEAN        DEFAULT FALSE,
 *         extensions        [0] IMPLICIT Extensions OPTIONAL }
 *
 *     MessageImprint ::= SEQUENCE {
 *         hashAlgorithm     AlgorithmIdentifier,
 *         hashedMessage     OCTET STRING }
 *
 *     TSAPolicyId ::= OBJECT IDENTIFIER
 *
 * </pre>
 */

public class TimeStampRequest extends ASN1Sequence {
    private ASN1Integer version;
    private MessageImprint msgImprint;
    private ASN1ObjectIdentifier policy;
    private ASN1Integer nonce;
    private ASN1Boolean certReq;
    private ASN1TaggedType extensions;


    public TimeStampRequest()
    {
        super(6);

        version = new ASN1Integer(1);
        add(version);

        msgImprint = new MessageImprint();
        add(msgImprint);

        policy = new ASN1ObjectIdentifier(true, true);
        add(policy);

        nonce = new ASN1Integer(true, true);
        add(nonce);

        certReq = new ASN1Boolean(false);
        add(certReq);

        extensions = new ASN1TaggedType(0, new ASN1Opaque(), false, true);
        add(extensions);
    }


    public TimeStampRequest(String digestAlg, byte[] digest)
        throws NoSuchAlgorithmException
    {
        super(6);

        version = new ASN1Integer(1);
        add(version);

        msgImprint = new MessageImprint(digestAlg, digest);
        add(msgImprint);

        policy = new ASN1ObjectIdentifier(true, true);
        add(policy);

        nonce = new ASN1Integer(true, true);
        add(nonce);

        certReq = new ASN1Boolean(false);
        add(certReq);

        // TODO What sort of extensions are supported
        extensions = new ASN1TaggedType(0, new ASN1Opaque(), false, true);
        add(extensions);
    }




    public AlgorithmIdentifier getHashAlgorithm()
    {
        return msgImprint.getHashAlgorithm();
    }

    public byte[] getHashedMessage()
    {
        byte[] digest = msgImprint.getHashedMessage();
        return (digest == null) ? null : digest.clone();
    }



    public void setPolicy(String policyId)
    {
        this.policy = new ASN1ObjectIdentifier(policyId);
        set(2, this.policy);
    }

    public String getPolicy()
    {
        return policy.toString();
    }


    public void setNonce(BigInteger nonce)
    {
        this.nonce = new ASN1Integer(nonce);
        set(3, this.nonce);
    }

    public BigInteger getNonce()
    {
        return nonce.getBigInteger();
    }


    public void setRequestCertificate(boolean value)
    {
        this.certReq = new ASN1Boolean(value);
        set(4, this.certReq);
    }

    public boolean isRequestCertificate()
    {
        return certReq.isTrue();
    }



    /**
     * Sets the Time-Stamp Protocol extensions.
     *
     * @param extensions The protocol extensions.
     */
    public void setExtensions(X509Extension[] extensions)
    {
        // TODO
        throw new UnsupportedOperationException();
    }


}
