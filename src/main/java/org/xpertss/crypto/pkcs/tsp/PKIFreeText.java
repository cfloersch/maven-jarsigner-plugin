package org.xpertss.crypto.pkcs.tsp;

import org.xpertss.crypto.asn1.ASN1SequenceOf;
import org.xpertss.crypto.asn1.ASN1UTF8String;
import org.xpertss.crypto.asn1.Decoder;

import java.io.IOException;

public class PKIFreeText extends ASN1SequenceOf {

    private String[] messages;

    public PKIFreeText()
    {
        super(ASN1UTF8String.class);
    }

    public String[] getMessages()
    {
        return messages;
    }


    public void decode(Decoder dec)
        throws IOException
    {
        super.decode(dec);
        messages = new String[size()];
        for(int i = 0; i < size(); i++) {
            messages[i] = (String) get(i).getValue();
        }
    }
}
