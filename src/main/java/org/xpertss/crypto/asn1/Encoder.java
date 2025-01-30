package org.xpertss.crypto.asn1;

import java.io.*;

/**
 * Defines the methods that must be implemented by encoders
 * of ASN.1 types.
 */
public interface Encoder {

   public void writeType(ASN1Type t)
      throws IOException;

   public void writeBoolean(ASN1Boolean t)
      throws IOException;

   public void writeInteger(ASN1Integer t)
      throws IOException;

   public void writeBitString(ASN1BitString t)
      throws IOException;

   public void writeOctetString(ASN1OctetString t)
      throws IOException;

   public void writeNull(ASN1Null t)
      throws IOException;

   public void writeObjectIdentifier(ASN1ObjectIdentifier t)
      throws IOException;

   public void writeReal(ASN1Real t)
      throws IOException;

   public void writeString(ASN1String t)
      throws IOException;

   public void writeCollection(ASN1Collection t)
      throws IOException;

   public void writeTime(ASN1Time t)
      throws IOException;

   public void writeTaggedType(ASN1TaggedType t)
      throws IOException;

   public void writeTypeIdentifier(ASN1Type t)
      throws IOException;

}

