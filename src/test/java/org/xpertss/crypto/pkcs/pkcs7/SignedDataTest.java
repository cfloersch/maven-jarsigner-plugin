package org.xpertss.crypto.pkcs.pkcs7;

import org.junit.jupiter.api.Test;
import org.xpertss.crypto.asn1.ASN1ObjectIdentifier;
import org.xpertss.crypto.asn1.ASN1Sequence;
import org.xpertss.crypto.asn1.AsnUtil;
import org.xpertss.crypto.asn1.DERDecoder;
import org.xpertss.crypto.pkcs.AlgorithmIdentifier;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 2/2/2025
 */
class SignedDataTest {

   @Test
   public void basicTest() throws Exception
   {
      /*
        So looking at the Sun code it would appear that PKCS7 is reading in a ContentInfo
        instance, and the contentType = SignedData
       */
      ASN1ObjectIdentifier ident = new ASN1ObjectIdentifier();
      SignedData signedData = new SignedData();

      ASN1Sequence wrapper = new ASN1Sequence(2);
      wrapper.add(ident);
      wrapper.add(signedData);

      ContentInfo content = new ContentInfo();

      try(DERDecoder decoder =  new DERDecoder(load("SERVER.RSA"))) {
         content.decode(decoder);
         System.out.println(content.getContent());
      } catch(IOException e) {
         //System.out.println(ident);
         throw e;
      }

      /*
      Class 0 (Universal): Bits 8 and 7 are both 0. This class includes common types like INTEGER, BOOLEAN, etc.link
      Class 1 (Application): Bit 8 is 0, bit 7 is 1. Used for application-specific types.
      Class 2 (Context-Specific): Bit 8 is 1, bit 7 is 0. Defined within the context of a specific structure.
      Class 3 (Private): Bits 8 and 7 are both 1. For privately defined types.
       */
   }


   private static InputStream load(String file) throws Exception
   {
      Path manifestPath = Paths.get("src","test", "resources", file);
      return Files.newInputStream(manifestPath);
   }

}