/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 2/1/2025
 */
package org.xpertss.crypto.pkcs.pkcs7;

import org.xpertss.crypto.asn1.ASN1Integer;
import org.xpertss.crypto.asn1.ASN1Opaque;
import org.xpertss.crypto.asn1.ASN1Sequence;
import org.xpertss.crypto.asn1.Decoder;
import org.xpertss.crypto.asn1.Encoder;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509Certificate;

public class IssuerAndSerialNumber extends ASN1Sequence {

   /**
    * The issuer name. Still of type ANY but being
    * replaced by RDName soon.
    */
   protected X500Principal issuer;

   /**
    * The serial number.
    */
   protected ASN1Integer serial;


   public IssuerAndSerialNumber()
   {
      super(2);

      /* Issuer and serial number */
      serial = new ASN1Integer();

      add(new ASN1Opaque());
      add(serial);
   }

   public IssuerAndSerialNumber(X509Certificate cert)
   {
      this(cert.getIssuerX500Principal(), cert.getSerialNumber());
   }
   public IssuerAndSerialNumber(X500Principal issuer, BigInteger serial)
   {
      super(2);

      /* Issuer and serial number */
      this.serial = new ASN1Integer(serial);
      this.issuer = issuer;

      add(new ASN1Opaque());
      add(this.serial);
   }


   /**
    * Returns the {@link X500Principal name} of the issuer of the certificate of this
    * signer.
    *
    * @return The issuer name.
    */
   public X500Principal getIssuerDN()
   {
      return issuer;
   }


   /**
    *
    * @return The serial number.
    */
   public BigInteger getSerialNumber()
   {
      return serial.getBigInteger();
   }


   /**
    * Encodes this <code>SignerInfo</code>.
    *
    * @param encoder The encoder to use.
    */
   public void encode(Encoder encoder)
      throws IOException
   {
      set(0, new ASN1Opaque(issuer.getEncoded()));
      super.encode(encoder);
   }

   public void decode(Decoder decoder)
      throws IOException
   {
      super.decode(decoder);
      ASN1Opaque o = (ASN1Opaque) get(0);
      this.issuer = new X500Principal(o.getEncoded());
   }


   public boolean equivalent(X509Certificate cert)
   {
      if (cert == null) throw new NullPointerException("Need a cert!");
      if (!issuer.equals(cert.getIssuerX500Principal())) return false;
      return serial.getBigInteger().equals(cert.getSerialNumber());
   }

}
