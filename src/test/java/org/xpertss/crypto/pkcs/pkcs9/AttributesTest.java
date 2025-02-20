package org.xpertss.crypto.pkcs.pkcs9;

import org.junit.jupiter.api.Test;
import org.xpertss.crypto.asn1.ASN1ObjectIdentifier;
import org.xpertss.crypto.asn1.ASN1Type;
import org.xpertss.crypto.asn1.AsnUtil;
import org.xpertss.crypto.pkcs.pkcs7.ContentInfo;
import sun.security.pkcs.PKCS9Attribute;
import sun.security.pkcs.PKCS9Attributes;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;


import static org.junit.jupiter.api.Assertions.*;

class AttributesTest {

    @Test
    public void testCompareWithSun() throws Exception
    {
        byte[] ts = load("timestamps", "DigitCert.ts");
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.14");

        PKCS9Attribute[] atts = new PKCS9Attribute[] {
                new PKCS9Attribute(PKCS9Attribute.SIGNATURE_TIMESTAMP_TOKEN_STR, ts)
        };

        PKCS9Attributes unauthAttrs = new PKCS9Attributes(atts);
        byte[] encoded = unauthAttrs.getDerEncoding();


        Attributes decoded = AsnUtil.decode(new Attributes(), encoded);
        assertEquals(1, decoded.size());

        Attribute attr = decoded.getAttribute(oid);
        assertEquals(1, attr.valueCount());
        assertNotNull(attr);

        ASN1Type value = attr.valueAt(0);
        assertNotNull(value);
        assertInstanceOf(ContentInfo.class, value);
        ContentInfo content = (ContentInfo) value;
        assertEquals(new ASN1ObjectIdentifier("1.2.840.113549.1.7.2"), content.getContentType());

    }







    private static byte[] load(String directory, String file) throws Exception
    {
        Path manifestPath = Paths.get("src","test", "resources", directory, file);
        return Files.readAllBytes(manifestPath);
    }
}