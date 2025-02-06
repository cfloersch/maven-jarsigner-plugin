package org.xpertss.crypto.pkcs.tsp;

import org.junit.jupiter.api.Test;
import org.xpertss.crypto.asn1.AsnUtil;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class TimeStampResponseTest {


    @Test
    public void testSimpleFailureEncodeDecode() throws Exception
    {
        boolean[] reasons = createReasons(TimeStampResponse.BAD_ALG, TimeStampResponse.UNACCEPTED_POLICY);
        TimeStampResponse response = new TimeStampResponse(TimeStampResponse.REJECTION, reasons);
        byte[] encoded = AsnUtil.encode(response);
        TimeStampResponse decoded = AsnUtil.decode(new TimeStampResponse(), encoded);

        assertEquals(TimeStampResponse.REJECTION, decoded.getStatusCode());

        assertTrue(decoded.isFailure(TimeStampResponse.BAD_ALG));
        assertTrue(decoded.isFailure(TimeStampResponse.UNACCEPTED_POLICY));
        assertFalse(decoded.isFailure(TimeStampResponse.BAD_REQUEST));
        assertFalse(decoded.isFailure(TimeStampResponse.SYSTEM_FAILURE));
        assertEquals(16, decoded.getFailureInfo().length);

        assertNull(decoded.getToken());
        assertNull(decoded.getTimestampTokenInfo());

        assertNull(decoded.getStatusMessages());
    }

    @Test
    public void testSimpleFailureMessageEncodeDecode() throws Exception
    {
        TimeStampResponse response = new TimeStampResponse(TimeStampResponse.REJECTION, "A simple reason");

        byte[] encoded = AsnUtil.encode(response);
        TimeStampResponse decoded = AsnUtil.decode(new TimeStampResponse(), encoded);

        assertEquals(TimeStampResponse.REJECTION, decoded.getStatusCode());

        assertFalse(decoded.isFailure(TimeStampResponse.BAD_ALG));
        assertFalse(decoded.isFailure(TimeStampResponse.UNACCEPTED_POLICY));
        assertFalse(decoded.isFailure(TimeStampResponse.BAD_REQUEST));
        assertFalse(decoded.isFailure(TimeStampResponse.SYSTEM_FAILURE));
        assertEquals(0, decoded.getFailureInfo().length);

        assertNull(decoded.getToken());
        assertNull(decoded.getTimestampTokenInfo());

        assertNotNull(decoded.getStatusMessages());
        assertEquals(1, decoded.getStatusMessages().length);
        assertEquals("A simple reason", decoded.getStatusMessages()[0]);
    }

    @Test
    public void testSimpleFailureMessageAndCodesEncodeDecode() throws Exception
    {
        boolean[] reasons = createReasons(TimeStampResponse.BAD_ALG, TimeStampResponse.UNACCEPTED_POLICY);
        TimeStampResponse response = new TimeStampResponse(TimeStampResponse.REJECTION, reasons, "A simple reason");

        byte[] encoded = AsnUtil.encode(response);
        TimeStampResponse decoded = AsnUtil.decode(new TimeStampResponse(), encoded);

        assertEquals(TimeStampResponse.REJECTION, decoded.getStatusCode());

        assertTrue(decoded.isFailure(TimeStampResponse.BAD_ALG));
        assertTrue(decoded.isFailure(TimeStampResponse.UNACCEPTED_POLICY));
        assertFalse(decoded.isFailure(TimeStampResponse.BAD_REQUEST));
        assertFalse(decoded.isFailure(TimeStampResponse.SYSTEM_FAILURE));
        assertEquals(16, decoded.getFailureInfo().length);

        assertNull(decoded.getToken());
        assertNull(decoded.getTimestampTokenInfo());

        assertNotNull(decoded.getStatusMessages());
        assertEquals(1, decoded.getStatusMessages().length);
        assertEquals("A simple reason", decoded.getStatusMessages()[0]);
    }



    private static boolean[] createReasons(int ... reasons)
    {
        Arrays.sort(reasons);
        int max = reasons[reasons.length - 1];
        boolean[] response = new boolean[max+1];
        for(int reason : reasons) response[reason] = true;
        return response;
    }
}