package org.xpertss.crypto.pkcs.tsp;

import org.junit.jupiter.api.Test;
import org.xpertss.crypto.asn1.AsnUtil;
import org.xpertss.crypto.pkcs.pkcs7.ContentInfo;
import org.xpertss.crypto.pkcs.pkcs7.SignedData;
import org.xpertss.crypto.pkcs.pkcs7.SignerInfo;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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






    // DigiCert response tests

    @Test
    public void testDigicertOkResponse() throws Exception
    {
        Path path = Paths.get("src", "test", "resources", "timestamps", "DigitCert-Good.tsr");
        byte[] encoded = Files.readAllBytes(path);
        TimeStampResponse response = AsnUtil.decode(new TimeStampResponse(), encoded);
        assertNotNull(response);

        assertEquals(0, response.getStatusCode());
        assertNull(response.getStatusMessages());
        assertEquals(0, response.getFailureInfo().length);
        assertEquals("the timestamp request was granted.", response.getStatusCodeAsText());

        TSTokenInfo tstInfo = response.getTimestampTokenInfo();
        assertNotNull(tstInfo);
        assertEquals(new BigInteger("11911547586292885239"), tstInfo.getNonce());

        ContentInfo token = response.getToken();
        assertNotNull(token);

        SignedData signedData = (SignedData) token.getContent();
        assertNotNull(signedData);
        SignerInfo signer = signedData.getSignerInfos().stream().findFirst().get();

        X500Principal principal = new X500Principal("CN=DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA, O=\"DigiCert, Inc.\", C=US");
        assertEquals(principal, signer.getIssuerDN());

        TSTokenInfo tstCopy = (TSTokenInfo) signedData.getContent();
        assertEquals(tstInfo, tstCopy);
    }

    @Test
    public void testDigicertBadResponse() throws Exception
    {
        Path path = Paths.get("src", "test", "resources", "timestamps", "DigitCert-Bad.tsr");
        byte[] encoded = Files.readAllBytes(path);
        TimeStampResponse response = AsnUtil.decode(new TimeStampResponse(), encoded);
        assertNotNull(response);
        System.out.println(response);

        assertEquals(2, response.getStatusCode());
        String[] statusMessages = response.getStatusMessages();;
        assertNotNull(statusMessages);
        assertEquals(1, statusMessages.length);
        assertEquals("unrecognized or unsupported Algorithm Identifier", statusMessages[0]);

        assertEquals(1, response.getFailureInfo().length);
        assertTrue(response.isFailure(TimeStampResponse.BAD_ALG));

        assertEquals("the timestamp request was rejected.", response.getStatusCodeAsText());

        TSTokenInfo tstInfo = response.getTimestampTokenInfo();
        assertNull(tstInfo);

        ContentInfo token = response.getToken();
        assertNull(token);
    }



    // TODO Add tests for GlobalSign and MicroSoft (Good and Bad)

    


    private static boolean[] createReasons(int ... reasons)
    {
        Arrays.sort(reasons);
        int max = reasons[reasons.length - 1];
        boolean[] response = new boolean[max+1];
        for(int reason : reasons) response[reason] = true;
        return response;
    }
}