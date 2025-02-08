/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 2/8/2025
 */
package org.xpertss.jarsigner.tsa;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.xpertss.crypto.pkcs.tsp.TimeStampRequest;
import java.math.BigInteger;
import java.net.URI;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

public class HttpTimestamperTest {

   private static final Map<String, URI> TSA = new LinkedHashMap<>();
   static {
      TSA.put("DigitCert", URI.create("http://timestamp.digicert.com"));
      TSA.put("MicroSoft", URI.create("http://timestamp.acs.microsoft.com"));
      TSA.put("GlobalSign", URI.create("http://rfc3161timestamp.globalsign.com/advanced"));
   }

   private static final byte[] SIGNATURE = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
      };

   @Test
   @Disabled
   public void testTimestampResponses() throws Exception
   {
      SecureRandom random = new SecureRandom();
      BigInteger NONCE = new BigInteger(64, random);

      for(Map.Entry<String, URI> e : TSA.entrySet()) {
         MessageDigest md = MessageDigest.getInstance("SHA-256");
         TimeStampRequest request = new TimeStampRequest(md.getAlgorithm(), md.digest(SIGNATURE));
         request.setNonce(NONCE);
         request.setRequestCertificate(true);
         HttpTimestamper timestamper = new HttpTimestamper(e.getValue());

         // TODO Test something
      }
   }







}
