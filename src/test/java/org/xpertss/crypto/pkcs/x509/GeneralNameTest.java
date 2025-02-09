package org.xpertss.crypto.pkcs.x509;

import org.junit.jupiter.api.Disabled;
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

   @Test
   public void testUriName() throws Exception
   {
      String uri = "https://www.helloworld.com/";

      GeneralName name = new GeneralName(GeneralName.uniformRessourceIdentifier, uri);
      byte[] encoded = AsnUtil.encode(name);

      GeneralName decoded = AsnUtil.decode(new GeneralName(), encoded);
      assertEquals(name, decoded);
      assertEquals(GeneralName.uniformRessourceIdentifier, decoded.getType());

      assertEquals(uri, decoded.getGeneralName().getValue());
   }


   @Test
   public void testDnsName() throws Exception
   {
      String host = "www.helloworld.com";

      GeneralName name = new GeneralName(GeneralName.dNSName, host);
      byte[] encoded = AsnUtil.encode(name);

      GeneralName decoded = AsnUtil.decode(new GeneralName(), encoded);
      assertEquals(name, decoded);
      assertEquals(GeneralName.dNSName, decoded.getType());

      assertEquals(host, decoded.getGeneralName().getValue());
   }


   @Test
   public void testRfcName() throws Exception
   {
      String email = "joe@nowhere.com";

      GeneralName name = new GeneralName(GeneralName.rfc822Name, email);
      byte[] encoded = AsnUtil.encode(name);

      GeneralName decoded = AsnUtil.decode(new GeneralName(), encoded);
      assertEquals(name, decoded);
      assertEquals(GeneralName.rfc822Name, decoded.getType());

      assertEquals(email, decoded.getGeneralName().getValue());
   }


   @Test
   public void testIpv4Name() throws Exception
   {
      byte[] addr = new byte[] { 10, 10, 1, 24 };


      String ip = "10.10.1.24";

      GeneralName name = new GeneralName(GeneralName.iPAddress, ip);
      byte[] encoded = AsnUtil.encode(name);

      GeneralName decoded = AsnUtil.decode(new GeneralName(), encoded);
      assertEquals(name, decoded);
      assertEquals(GeneralName.iPAddress, decoded.getType());
      assertEquals(ip, decoded.toString());  // NOTE due to compression probably doesn't work with IPv6

      assertArrayEquals(addr, (byte[])decoded.getGeneralName().getValue());
   }

   @Test
   public void testIpv6Name() throws Exception
   {
      byte[] addr = new byte[] {
         (byte) 0x20, (byte) 0x01, (byte) 0x0D, (byte) 0xB8, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
         (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78
      };


      String ip = "2001:db8::1234:5678";

      GeneralName name = new GeneralName(GeneralName.iPAddress, ip);
      byte[] encoded = AsnUtil.encode(name);

      GeneralName decoded = AsnUtil.decode(new GeneralName(), encoded);
      assertEquals(name, decoded);
      assertEquals(GeneralName.iPAddress, decoded.getType());

      assertArrayEquals(addr, (byte[])decoded.getGeneralName().getValue());
   }


   @Test
   @Disabled
   public void testToString() throws Exception
   {
      GeneralName ip4 = new GeneralName(GeneralName.iPAddress, "255.255.255.255");
      System.out.println("IP4: " + ip4.toString());

      GeneralName ip6 = new GeneralName(GeneralName.iPAddress, "2001:db8::1234:5678");
      System.out.println("IP6: " + ip6.toString());

      GeneralName dns = new GeneralName(GeneralName.dNSName, "www.google.com");
      System.out.println("DNS: " + dns.toString());

      GeneralName uri = new GeneralName(GeneralName.uniformRessourceIdentifier, "https://www.google.com/v1");
      System.out.println("URI: " + uri.toString());

      GeneralName oid = new GeneralName(GeneralName.registeredID, "1.4.840.315459.4.1");
      System.out.println("OID: " + oid.toString());

      GeneralName x500 = new GeneralName(GeneralName.directoryName, TEST_X500);
      System.out.println("X500: " + x500.toString());

      GeneralName rfc = new GeneralName(GeneralName.rfc822Name, "joe@nowhere.com");
      System.out.println("RFC: " + rfc.toString());


   }




}