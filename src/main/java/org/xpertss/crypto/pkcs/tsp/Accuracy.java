package org.xpertss.crypto.pkcs.tsp;

import org.xpertss.crypto.asn1.ASN1Integer;
import org.xpertss.crypto.asn1.ASN1Sequence;
import org.xpertss.crypto.asn1.ASN1TaggedType;

import java.math.BigInteger;

/**
 * <pre>
 *    Accuracy ::= SEQUENCE {
 *          seconds        INTEGER              OPTIONAL,
 *          millis     [0] INTEGER  (1..999)    OPTIONAL,
 *          micros     [1] INTEGER  (1..999)    OPTIONAL  }
 * </pre>
 */
class Accuracy extends ASN1Sequence {

    private ASN1Integer seconds;
    private ASN1Integer millis;
    private ASN1Integer micros;

    public Accuracy()
    {
        super(3, true, true);
        seconds = new ASN1Integer(true, true);
        add(seconds);
        millis = new ASN1Integer();
        add(new ASN1TaggedType(0, millis, false, true));
        micros = new ASN1Integer();
        add(new ASN1TaggedType(1, micros, false, true));
    }


    public int getSeconds()
    {
        return narrow(seconds, "seconds");
    }

    public int getMillis()
    {
        return narrow(millis, "millis");
    }

    public int getMicros()
    {
        return narrow(micros, "micros");
    }


    private static int narrow(ASN1Integer i, String field)
    {
        BigInteger bi = i.getBigInteger();
        if(bi.compareTo(BigInteger.ZERO) < 0
                || bi.compareTo(BigInteger.valueOf(1000)) >= 0)
                    throw new ArithmeticException(String.format("%s is out of bounds", field));
        return bi.intValueExact();
    }

}
