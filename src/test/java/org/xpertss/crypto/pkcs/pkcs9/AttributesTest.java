package org.xpertss.crypto.pkcs.pkcs9;

import org.junit.jupiter.api.Test;
import org.xpertss.crypto.asn1.ASN1ObjectIdentifier;
import org.xpertss.crypto.asn1.ASN1OctetString;
import org.xpertss.crypto.asn1.ASN1Type;
import org.xpertss.crypto.asn1.AsnUtil;

import static org.junit.jupiter.api.Assertions.*;

class AttributesTest {

    private static final byte[] TS = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    @Test
    public void testSimpleTimeStampAttribute() throws Exception
    {
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.14");
        Attribute attribute = new Attribute(oid, new ASN1OctetString(TS));

        Attributes attributes = new Attributes();
        attributes.addAttribute(attribute);

        byte[] encoded = AsnUtil.encode(attributes);
        Attributes decoded = AsnUtil.decode(new Attributes(), encoded);

        assertEquals(attributes.size(), decoded.size());

        Attribute attr = decoded.getAttribute(oid);
        assertNotNull(attr);

        ASN1Type value = attr.valueAt(0);
        assertNotNull(value);
        assertInstanceOf(ASN1OctetString.class, value);
        assertArrayEquals(TS, ((ASN1OctetString)value).getByteArray());
    }

    // TODO What other tests can I add here??

}