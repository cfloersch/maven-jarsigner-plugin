package org.xpertss.crypto.pkcs.pkcs7;

import org.junit.jupiter.api.Test;
import org.xpertss.crypto.asn1.DERDecoder;

import javax.security.auth.x500.X500Principal;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 2/2/2025
 */
class SignedDataTest {

   @Test
   public void testFullDecodeOfJDKJarSignerSignatureBlock() throws Exception
   {
      X500Principal issuer = new X500Principal("CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1, O=\"DigiCert, Inc.\", C=US");
      BigInteger serial = new BigInteger("12103026106566223692519392944031625835");

      // Assumption is the SignatureBlock is ContentInfo with a SignedData content item
      ContentInfo content = new ContentInfo();

      try(DERDecoder decoder =  new DERDecoder(load("SERVER.RSA"))) {
         content.decode(decoder);
      }
      SignedData signedData = (SignedData) content.getContent();
      List<SignerInfo> signers = signedData.getSignerInfos();
      assertEquals(1, signers.size());
      SignerInfo signer = signers.get(0);
      assertEquals(serial, signer.getSerialNumber());
      assertEquals(issuer, signer.getIssuerDN());
      List<X509Certificate> chain = signedData.getCertificates().getCertificates(issuer, serial);
      assertEquals(3, chain.size());
      assertEquals(serial, chain.get(0).getSerialNumber());
   }

   @Test
   public void testSigning() throws Exception
   {

   }



   private static InputStream load(String file) throws Exception
   {
      Path manifestPath = Paths.get("src","test", "resources", file);
      return Files.newInputStream(manifestPath);
   }

}