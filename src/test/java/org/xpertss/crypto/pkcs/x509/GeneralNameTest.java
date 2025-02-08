package org.xpertss.crypto.pkcs.x509;

import org.junit.jupiter.api.Test;
import org.xpertss.crypto.asn1.AsnUtil;

import javax.security.auth.x500.X500Principal;

import static org.junit.jupiter.api.Assertions.*;

/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 2/8/2025
 */
class GeneralNameTest {

   private static final String TEST_X500 = "CN=Microsoft Public RSA Time Stamping Authority, O=Microsoft Corporation, L=Redmond, ST=Washington, C=US";
   @Test
   public void testEncodeDecodeDirectoryName() throws Exception
   {
      X500Principal principal = new X500Principal(TEST_X500);
      GeneralName generalName = new GeneralName(principal);
      byte[] encoded = AsnUtil.encode(generalName);
      GeneralName decoded = AsnUtil.decode(new GeneralName(), encoded);
      assertEquals(TEST_X500, decoded.toString());
      byte[] rencoded = AsnUtil.encode(decoded);
      assertArrayEquals(encoded, rencoded);

      System.out.println(decoded);

   }

   @Test
   public void testDirectoryNameConstructors() throws Exception
   {
      X500Principal principal = new X500Principal(TEST_X500);
      GeneralName gnOne = new GeneralName(principal);
      byte[] encOne = AsnUtil.encode(gnOne);

      GeneralName gnTwo = new GeneralName(GeneralName.directoryName, TEST_X500);
      byte[] encTwo = AsnUtil.encode(gnTwo);

      assertArrayEquals(encOne, encTwo);
   }


}