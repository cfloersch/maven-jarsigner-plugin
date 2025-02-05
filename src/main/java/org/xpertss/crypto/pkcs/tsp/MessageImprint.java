package org.xpertss.crypto.pkcs.tsp;

import org.xpertss.crypto.asn1.ASN1OctetString;
import org.xpertss.crypto.asn1.ASN1Sequence;
import org.xpertss.crypto.pkcs.AlgorithmId;
import org.xpertss.crypto.pkcs.AlgorithmIdentifier;

import java.security.NoSuchAlgorithmException;

/**
 *    MessageImprint ::= SEQUENCE  {
 *         hashAlgorithm                AlgorithmIdentifier,
 *         hashedMessage                OCTET STRING  }
 */
public class MessageImprint extends ASN1Sequence {

    private AlgorithmIdentifier hashAlg;
    private ASN1OctetString hashedMsg;

    public MessageImprint()
    {
        super(2);

        hashAlg = new AlgorithmIdentifier();
        add(hashAlg);

        hashedMsg = new ASN1OctetString();
        add(hashedMsg);
    }

    public MessageImprint(String digestAlg, byte[] digest)
        throws NoSuchAlgorithmException
    {
        super(2);
        hashAlg = new AlgorithmIdentifier(AlgorithmId.lookup(digestAlg));
        add(hashAlg);

        hashedMsg = new ASN1OctetString(digest);
        add(hashedMsg);
    }



    public AlgorithmIdentifier getHashAlgorithm()
    {
        return hashAlg;
    }

    public byte[] getHashedMessage()
    {
        return hashedMsg.getByteArray();
    }





}
