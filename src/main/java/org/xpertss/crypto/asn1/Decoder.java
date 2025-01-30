package org.xpertss.crypto.asn1;

import java.io.*;

/**
 * Defines the methods that must be implemented by decoders
 * of ASN.1 types.
 */
public interface Decoder {

   public ASN1Type readType()
      throws IOException;

   public void readType(ASN1Type t)
      throws IOException;

   public void readBoolean(ASN1Boolean t)
      throws IOException;

   public void readInteger(ASN1Integer t)
      throws IOException;

   public void readBitString(ASN1BitString t)
      throws IOException;

   public void readOctetString(ASN1OctetString t)
      throws IOException;

   public void readNull(ASN1Null t)
      throws IOException;

   public void readObjectIdentifier(ASN1ObjectIdentifier t)
      throws IOException;

   public void readReal(ASN1Real t)
      throws IOException;

   public void readString(ASN1String t)
      throws IOException;

   public void readCollection(ASN1Collection t)
      throws IOException;

   public void readCollectionOf(ASN1CollectionOf t)
      throws IOException;

   public void readTime(ASN1Time t)
      throws IOException;

   public void readTaggedType(ASN1TaggedType t)
      throws IOException;

   public void readChoice(ASN1Choice t)
      throws IOException;

}

