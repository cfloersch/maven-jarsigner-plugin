package org.xpertss.crypto.pkcs.tsp;

import org.xpertss.crypto.asn1.*;
import org.xpertss.crypto.pkcs.AlgorithmIdentifier;
import org.xpertss.crypto.pkcs.x509.GeneralName;

import java.io.IOException;
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
 * <p/>
 * id-ct-TSTInfo  OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1) 4
 * }
 * <p/>
 * 1.2.840.113549.1.9.16.1.4
 */
public class TSTokenInfo extends ASN1Sequence implements ASN1RegisteredType {

    private ASN1Integer version;
    private ASN1ObjectIdentifier policy;
    private MessageImprint msgImprint;
    private ASN1Integer serial;
    private ASN1GeneralizedTime timestamp;
    private Accuracy accuracy;
    private ASN1Boolean ordering;
    private ASN1Integer nonce;
    private GeneralName tsa;
    private ASN1SequenceOf extensions;

    /**
     * Construct an uninitialized instance ready to decode a stream into
     */
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
        ordering.setOptional(true);
        add(ordering);

        nonce = new ASN1Integer(true, true);
        add(nonce);


        tsa = new GeneralName();
        add(new ASN1TaggedType(0, new ASN1OctetString(), false, true));


        extensions = new ASN1SequenceOf(ASN1Opaque.class);
        add(new ASN1TaggedType(1, extensions, false, true));
    }


    // TODO Create creators.. Possibly one from the request
    //  (policy and message imprint along with nonce and extensions are generally copyable)
    public TSTokenInfo(String digestAlg, byte[] digest, BigInteger serial, Date timestamp)
        throws NoSuchAlgorithmException
    {
        // Used by time stamp providers to create a response
    }




    @Override
    public ASN1ObjectIdentifier getOID()
    {
        return new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.1.4");
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
        byte[] digest = msgImprint.getHashedMessage();
        return (digest == null) ? null : digest.clone();
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


    public void decode(Decoder decoder)
        throws IOException
    {
        super.decode(decoder);
    }

}
