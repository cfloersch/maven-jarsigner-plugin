package org.xpertss.crypto.pkcs.tsp;

import org.junit.jupiter.api.Test;
import org.xpertss.crypto.asn1.ASN1ObjectIdentifier;
import org.xpertss.crypto.asn1.AsnUtil;
import org.xpertss.crypto.pkcs.AlgorithmId;
import org.xpertss.crypto.pkcs.AlgorithmIdentifier;
import org.xpertss.crypto.pkcs.pkcs7.ContentInfo;
import org.xpertss.crypto.pkcs.pkcs7.SignedData;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 2/7/2025
 */
class TSTokenInfoTest {

   private static final BigInteger NONCE = new BigInteger("4477040867524275589");
   private static final AlgorithmIdentifier hashIdent = new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"));

   @Test
   public void testDigicertToken() throws Exception
   {
      byte[] encoded = load("DigitCert.ts");
      ContentInfo content = AsnUtil.decode(new ContentInfo(), encoded);
      assertNotNull(content);
      SignedData signedData = (SignedData) content.getContent();
      assertNotNull(signedData);
      TSTokenInfo tstInfo = (TSTokenInfo) signedData.getContent();
      assertNotNull(tstInfo);
      assertEquals(hashIdent, tstInfo.getHashAlgorithm());
      assertEquals(32, tstInfo.getHashedMessage().length);
      assertEquals(NONCE, tstInfo.getNonce());
      assertNotNull(tstInfo.getPolicyID());
      assertEquals("2.16.840.1.114412.7.1", tstInfo.getPolicyID());
      assertEquals(new BigInteger("151283616440287569804835811747875277570"), tstInfo.getSerialNumber());
   }



   @Test
   public void testGlobalSignToken() throws Exception
   {
      byte[] encoded = load("GlobalSign.ts");
      ContentInfo content = AsnUtil.decode(new ContentInfo(), encoded);
      assertNotNull(content);
      SignedData signedData = (SignedData) content.getContent();
      assertNotNull(signedData);
      TSTokenInfo tstInfo = (TSTokenInfo) signedData.getContent();
      assertNotNull(tstInfo);
      assertEquals(hashIdent, tstInfo.getHashAlgorithm());
      assertEquals(32, tstInfo.getHashedMessage().length);
      assertEquals(NONCE, tstInfo.getNonce());
      assertNotNull(tstInfo.getPolicyID());
      assertEquals("1.3.6.1.4.1.4146.2.3", tstInfo.getPolicyID());
      assertEquals(new BigInteger("307522907613851416694125661223718855633298980549"), tstInfo.getSerialNumber());
   }


   @Test
   public void testMicroSoftToken() throws Exception
   {
      byte[] encoded = load("MicroSoft.ts");
      ContentInfo content = AsnUtil.decode(new ContentInfo(), encoded);
      assertNotNull(content);
      SignedData signedData = (SignedData) content.getContent();
      assertNotNull(signedData);
      TSTokenInfo tstInfo = (TSTokenInfo) signedData.getContent();
      assertNotNull(tstInfo);
      assertEquals(hashIdent, tstInfo.getHashAlgorithm());
      assertEquals(32, tstInfo.getHashedMessage().length);
      assertEquals(NONCE, tstInfo.getNonce());
      assertNotNull(tstInfo.getPolicyID());
      assertEquals("1.3.6.1.4.1.601.10.3.1", tstInfo.getPolicyID());
      assertEquals(new BigInteger("113918696925722"), tstInfo.getSerialNumber());
   }



   private static byte[] load(String file) throws Exception
   {
      Path path = Paths.get("src","test", "resources", "timestamps", file);
      return Files.readAllBytes(path);
   }

}