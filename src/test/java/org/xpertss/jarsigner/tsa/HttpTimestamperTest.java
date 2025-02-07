package org.xpertss.jarsigner.tsa;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.xpertss.crypto.asn1.ASN1ObjectIdentifier;
import org.xpertss.crypto.asn1.AsnUtil;
import org.xpertss.crypto.pkcs.AlgorithmId;
import org.xpertss.crypto.pkcs.AlgorithmIdentifier;
import org.xpertss.crypto.pkcs.pkcs7.ContentInfo;
import org.xpertss.crypto.pkcs.pkcs7.SignedData;
import org.xpertss.crypto.pkcs.tsp.TSTokenInfo;
import sun.security.timestamp.TSRequest;
import sun.security.timestamp.TSResponse;
import sun.security.timestamp.HttpTimestamper;

import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class HttpTimestamperTest {

    private static final byte[] SIGNATURE = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };



    @Test@Disabled
    public void testSunHttpTimeStamper() throws Exception
    {
        // http://timestamp.digicert.com            (No GeneralName nor Accuracy)
        // http://timestamp.acs.microsoft.com       (Both GeneralName and Accuracy with millis)
        // http://rfc3161timestamp.globalsign.com/advanced  (Accuracy in seconds - not sure what sort of GeneralName)

        URI tsaURI = URI.create("http://timestamp.globalsign.com/tsa/r6advanced1"); //

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        TSRequest tsQuery = new TSRequest(null, SIGNATURE, md);
        SecureRandom random = new SecureRandom();
        tsQuery.setNonce(new BigInteger(64, random));
        tsQuery.requestCertificate(true);

        HttpTimestamper tsa = new HttpTimestamper(tsaURI);
        TSResponse tsReply = tsa.generateTimestamp(tsQuery);

        assertEquals(TSResponse.GRANTED, tsReply.getStatusCode());

        byte[] encoded = tsReply.getEncodedToken();



        ContentInfo content = AsnUtil.decode(new ContentInfo(), encoded);
        //System.out.println(content);

        // TODO Find a way to make getContent generic or more friendly
        //  possibly tie it in with getContentType() which can return a Class as an example
        //  do I want all of the Content Impls to extends from a common class?
        //  They are all Sequences (except data itself which is OctetString)
        SignedData signedData = (SignedData) content.getContent();

        // Not sure why content is an OctetString and not an actual TSTokenInfo instance..
        // Maybe something to do with my definition of implicit/explicit?
        System.out.println("ContentType: " + signedData.getContentType());
        System.out.println(signedData.getContent());
        System.out.println();

        TSTokenInfo tstInfo = (TSTokenInfo) signedData.getContent();

        System.out.println(tstInfo);

    }





    private static final Map<String,URI> TSA = new LinkedHashMap<>();
    static {
        TSA.put("DigitCert", URI.create("http://timestamp.digicert.com"));
        TSA.put("MicroSoft", URI.create("http://timestamp.acs.microsoft.com"));
        TSA.put("GlobalSign", URI.create("http://rfc3161timestamp.globalsign.com/advanced"));
    }

    @Test@Disabled
    public void testStoreTimestampTokens() throws Exception
    {
        SecureRandom random = new SecureRandom();
        BigInteger NONCE = new BigInteger(64, random);

        for(Map.Entry<String,URI> e : TSA.entrySet()) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            TSRequest tsQuery = new TSRequest(null, SIGNATURE, md);
            tsQuery.setNonce(NONCE);
            tsQuery.requestCertificate(true);

            HttpTimestamper tsa = new HttpTimestamper(e.getValue());
            TSResponse tsReply = tsa.generateTimestamp(tsQuery);

            assertEquals(TSResponse.GRANTED, tsReply.getStatusCode());

            byte[] encoded = tsReply.getEncodedToken();
            Path path = Paths.get("src", "test", "resources", "timestamps", e.getKey() + ".ts");
            Files.write(path, encoded, StandardOpenOption.CREATE_NEW);
        }
    }

    @Test
    public void testTimestamps() throws Exception
    {
        BigInteger NONCE = new BigInteger("4477040867524275589");
        ASN1ObjectIdentifier hashIdent = AlgorithmId.lookup("SHA-256");
        for(Map.Entry<String,URI> e : TSA.entrySet()) {
            Path path = Paths.get("src", "test", "resources", "timestamps", e.getKey() + ".ts");
            byte[] encoded = Files.readAllBytes(path);
            ContentInfo content = AsnUtil.decode(new ContentInfo(), encoded);
            assertNotNull(content);
            SignedData signedData = (SignedData) content.getContent();
            assertNotNull(signedData);
            TSTokenInfo tstInfo = (TSTokenInfo) signedData.getContent();
            assertNotNull(tstInfo);
            assertEquals(new AlgorithmIdentifier(hashIdent), tstInfo.getHashAlgorithm());
            assertEquals(32, tstInfo.getHashedMessage().length);
            assertEquals(NONCE, tstInfo.getNonce());
            assertNotNull(tstInfo.getPolicyID());
        }
    }


}