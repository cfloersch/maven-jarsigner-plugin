package org.xpertss.crypto.asn1;

import java.io.IOException;


/**
 * Represents the ASN.1 NULL type.
 */
public class ASN1Null extends ASN1AbstractType implements Cloneable {

   public Object getValue()
   {
      return null;
   }

   public int getTag()
   {
      return ASN1.TAG_NULL;
   }


   public void encode(Encoder enc)
      throws IOException
   {
      enc.writeNull(this);
   }

   public void decode(Decoder dec)
      throws IOException
   {
      dec.readNull(this);
   }


   public String toString()
   {
      return "NULL";
   }
   
   public ASN1Type copy()
   {
      try { 
         return (ASN1Null) super.clone();
      } catch (CloneNotSupportedException e) { 
         // this shouldn't happen, since we are Cloneable
         throw new InternalError();
      }
   }

   public boolean equals(Object obj)
   {
      return (obj instanceof ASN1Null);
   }
   
}




