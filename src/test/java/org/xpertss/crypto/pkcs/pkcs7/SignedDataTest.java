package org.xpertss.crypto.pkcs.pkcs7;

import org.junit.jupiter.api.Test;
import org.xpertss.crypto.asn1.DERDecoder;
import org.xpertss.crypto.asn1.DEREncoder;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
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
      List<X509Certificate> chain = signedData.getCertificates(issuer, serial);
      assertEquals(3, chain.size());
      assertEquals(serial, chain.get(0).getSerialNumber());



   }

   @Test
   public void testSigning() throws Exception
   {
      byte[] signature = new byte[] { 0x00, 0x01, 0x02, 0x03 };

      CertificateFactory factory = CertificateFactory.getInstance("X509");
      ByteArrayOutputStream baos = new ByteArrayOutputStream();

      try(InputStream in = load("server-cert-path.crt")) {
         while(in.available() > 0) {
            CertPath certPath = factory.generateCertPath(in, "PKCS7");

            SignedData signedData = new SignedData();
            signedData.setContentType(ContentInfo.DATA_OID);
            SignerInfo signer = signedData.newSigner("SHA256withRSA", certPath); // certs are backwards
            signer.setEncryptedDigest(signature);

            ContentInfo content = new ContentInfo(signedData);
            try(DEREncoder encoder = new DEREncoder(baos)) {
               content.encode(encoder);
            }
         }
      }

      try(InputStream in = new ByteArrayInputStream(baos.toByteArray())) {
         ContentInfo content = new ContentInfo();
         try(DERDecoder decoder =  new DERDecoder(in)) {
            content.decode(decoder);
         }
         assertEquals(ContentInfo.SIGNED_DATA_OID, content.getContentType());
         SignedData signedData = (SignedData) content.getContent();
         assertEquals(3, signedData.getCertificates().size());
         List<SignerInfo> signers = signedData.getSignerInfos();
         assertEquals(1, signers.size());
      }

   }


   @Test
   public void testReadCertChainFile() throws Exception
   {
      CertificateFactory factory = CertificateFactory.getInstance("X509");

      try(InputStream in = load("server-cert-chain.pem")) {
         Collection<? extends Certificate> chain = factory.generateCertificates(in);
         assertEquals(3, chain.size());
      }

      try(InputStream in = load("server-cert-path.crt")) {
         ContentInfo content = new ContentInfo();
         try(DERDecoder decoder =  new DERDecoder(in)) {
            content.decode(decoder);
         }
         assertEquals(ContentInfo.SIGNED_DATA_OID, content.getContentType());
         SignedData signedData = (SignedData) content.getContent();
         assertEquals(3, signedData.getCertificates().size());

      }

      try(InputStream in = load("server-cert-path.crt")) {
         CertPath certPath = factory.generateCertPath(in, "PKCS7");
         assertEquals(3, certPath.getCertificates().size());
      }

   }


   private static void dump(Collection<X509Certificate> certs)
   {
      int i = 0;
      for(X509Certificate cert : certs) {
         System.out.printf("Certificate[%d] {%n", i++);
         System.out.printf("  SubjectDN: %s%n", cert.getSubjectDN());
         System.out.printf("  IssuerDN:  %s%n", cert.getIssuerDN());
         System.out.printf("  Serial:    %s%n", cert.getSerialNumber());
         System.out.printf("  Algorithm: %s%n", cert.getSigAlgName());
         System.out.println("}");
      }
   }


   private static InputStream load(String file) throws Exception
   {
      Path manifestPath = Paths.get("src","test", "resources", file);
      return Files.newInputStream(manifestPath);
   }

}