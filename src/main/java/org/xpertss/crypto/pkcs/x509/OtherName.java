/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 2/8/2025
 */
package org.xpertss.crypto.pkcs.x509;

import org.xpertss.crypto.asn1.ASN1ObjectIdentifier;
import org.xpertss.crypto.asn1.ASN1OpenType;
import org.xpertss.crypto.asn1.ASN1Sequence;
import org.xpertss.crypto.asn1.ASN1TaggedType;
import org.xpertss.crypto.asn1.ASN1Type;
import org.xpertss.crypto.asn1.OIDRegistry;
import org.xpertss.crypto.pkcs.PKCSRegistry;

/**
 * <pre>
 *   OtherName ::= SEQUENCE {
 *     type-id    OBJECT IDENTIFIER,
 *     value      [0] ANY DEFINED BY type-id
 *   }
 * </pre>
 */
public class OtherName extends ASN1Sequence {

   private ASN1ObjectIdentifier otherNameID;
   private ASN1TaggedType otherNameValue;


   public OtherName()
   {
      this(PKCSRegistry.getDefaultRegistry());
   }


   public OtherName(OIDRegistry registry)
   {
      super(2);
      if (registry == null) registry = PKCSRegistry.getDefaultRegistry();

      otherNameID = new ASN1ObjectIdentifier();
      add(otherNameID);

      otherNameValue = new ASN1TaggedType(0, new ASN1OpenType(registry, otherNameID), true, false) ;
      add(otherNameValue);
   }



   // TODO creators



   public ASN1ObjectIdentifier getOID()
   {
      return otherNameID;
   }

   public ASN1Type getValue()
   {
      ASN1Type o = otherNameValue.getInnerType();
      if (o instanceof ASN1OpenType) return null;  // shouldn't happen
      return o;
   }

}
