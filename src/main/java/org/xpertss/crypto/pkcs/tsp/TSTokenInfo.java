package org.xpertss.crypto.pkcs.tsp;

import org.xpertss.crypto.asn1.*;
import org.xpertss.crypto.pkcs.AlgorithmIdentifier;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Extension;
import java.util.Date;

/**
 * This class provides the timestamp token info resulting from a successful
 * timestamp request, as defined in
 * <a href="http://www.ietf.org/rfc/rfc3161.txt">RFC 3161</a>.
 * <p/>
 * The timestampTokenInfo ASN.1 type has the following definition:
 * <pre>
 *
 *     TSTInfo ::= SEQUENCE {
 *         version                INTEGER  { v1(1) },
 *         policy                 TSAPolicyId,
 *         messageImprint         MessageImprint,
 *           -- MUST have the same value as the similar field in
 *           -- TimeStampReq
 *         serialNumber           INTEGER,
 *          -- Time-Stamping users MUST be ready to accommodate integers
 *          -- up to 160 bits.
 *         genTime                GeneralizedTime,
 *         accuracy               Accuracy                 OPTIONAL,
 *         ordering               BOOLEAN             DEFAULT FALSE,
 *         nonce                  INTEGER                  OPTIONAL,
 *           -- MUST be present if the similar field was present
 *           -- in TimeStampReq.  In that case it MUST have the same value.
 *         tsa                    [0] GeneralName          OPTIONAL,
 *         extensions             [1] IMPLICIT Extensions  OPTIONAL }
 *
 *     Accuracy ::= SEQUENCE {
 *         seconds        INTEGER           OPTIONAL,
 *         millis     [0] INTEGER  (1..999) OPTIONAL,
 *         micros     [1] INTEGER  (1..999) OPTIONAL  }
 *
 *     TSAPolicyId ::= OBJECT IDENTIFIER
 * </pre>
 */
public class TSTokenInfo extends ASN1Sequence {

    private ASN1Integer version;
    private ASN1ObjectIdentifier policy;
    private MessageImprint msgImprint;
    private ASN1Integer serial;
    private ASN1GeneralizedTime timestamp;
    private Accuracy accuracy;
    private ASN1Boolean ordering;
    private ASN1Integer nonce;
    private ASN1TaggedType tsa;
    private ASN1TaggedType extensions;

    public TSTokenInfo()
    {
        super(10);

        version = new ASN1Integer(1);
        add(version);

        policy = new ASN1ObjectIdentifier();
        add(policy);

        msgImprint = new MessageImprint();
        add(msgImprint);

        serial = new ASN1Integer();
        add(serial);

        timestamp = new ASN1GeneralizedTime();
        add(timestamp);

        accuracy = new Accuracy();
        add(accuracy);

        ordering = new ASN1Boolean(false);
        add(ordering);

        nonce = new ASN1Integer(true, true);
        add(nonce);

        // TODO What is a GeneralName (X500Principal or can it be much more)
        tsa = new ASN1TaggedType(0, new ASN1Opaque(), true, true);
        add(tsa);

        // TODO What sort of extensions are supported
        extensions = new ASN1TaggedType(1, new ASN1Opaque(), false, true);
        add(extensions);

    }


    public TSTokenInfo(String digestAlg, byte[] digest, BigInteger serial, Date timestamp)
        throws NoSuchAlgorithmException
    {

    }


    /**
     * Extract the date and time from the timestamp token.
     *
     * @return The date and time when the timestamp was generated.
     */
    public Date getDate()
    {
        return timestamp.getDate();
    }

    public AlgorithmIdentifier getHashAlgorithm()
    {
        return msgImprint.getHashAlgorithm();
    }

    public byte[] getHashedMessage()
    {
        // TODO Check hashed message for null
        return msgImprint.getHashedMessage().clone();
    }

    public BigInteger getNonce()
    {
        return nonce.getBigInteger();
    }

    public String getPolicyID()
    {
        return policy.toString();
    }

    public BigInteger getSerialNumber()
    {
        return serial.getBigInteger();
    }

    /**
     * Gets the Time-Stamp Protocol extensions.
     */
    public X509Extension[] getExtensions()
    {
        // TODO
        throw new UnsupportedOperationException();
    }

}
