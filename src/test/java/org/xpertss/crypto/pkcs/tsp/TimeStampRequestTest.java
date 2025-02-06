package org.xpertss.crypto.pkcs.tsp;

import org.junit.jupiter.api.Test;
import org.xpertss.crypto.asn1.ASN1ObjectIdentifier;
import org.xpertss.crypto.asn1.AsnUtil;
import org.xpertss.crypto.pkcs.AlgorithmIdentifier;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class TimeStampRequestTest {

    private static final byte[] DIGEST = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                                            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };

    private static final ASN1ObjectIdentifier hashAlg = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1");



    @Test
    public void testTSRequestEncodeDecode() throws Exception
    {
        TimeStampRequest request = new TimeStampRequest("SHA256", DIGEST);
        request.setRequestCertificate(true);
        request.setNonce(BigInteger.TEN);

        byte[] encoded = AsnUtil.encode(request);
        TimeStampRequest decoded = AsnUtil.decode(new TimeStampRequest(), encoded);
        assertEquals(request.isRequestCertificate(), decoded.isRequestCertificate());
        assertEquals(request.getNonce(), decoded.getNonce());
        assertEquals(request.getHashAlgorithm(), decoded.getHashAlgorithm());
        assertArrayEquals(request.getHashedMessage(), decoded.getHashedMessage());
    }

    @Test
    public void testTSRequestEncodeDecodeDefaults() throws Exception
    {
        TimeStampRequest request = new TimeStampRequest("SHA256", DIGEST);
        byte[] encoded = AsnUtil.encode(request);
        TimeStampRequest decoded = AsnUtil.decode(new TimeStampRequest(), encoded);

        assertFalse(decoded.isRequestCertificate());
        assertNull(decoded.getNonce());
        assertNull(decoded.getPolicy());


        assertEquals(new AlgorithmIdentifier(hashAlg), decoded.getHashAlgorithm());
        assertEquals(request.getHashAlgorithm(), decoded.getHashAlgorithm());
        assertArrayEquals(request.getHashedMessage(), decoded.getHashedMessage());
    }


}