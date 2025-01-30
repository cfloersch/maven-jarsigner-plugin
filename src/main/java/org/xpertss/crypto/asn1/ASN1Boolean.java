package org.xpertss.crypto.asn1;

import java.io.IOException;


/**
 * Represents an ASN.1 BOOLEAN type. The corresponding Java 
 * type is <code>boolean</code>. This type does not support 
 * constraint checking.
 */
public class ASN1Boolean extends ASN1AbstractType {

   private boolean value_ = true;


   public ASN1Boolean()
   {
   }


   public ASN1Boolean(boolean optional, boolean explicit)
   {
      super(optional, explicit);
   }


   public ASN1Boolean(boolean t)
   {
      setTrue(t);
   }




   public Object getValue()
   {
      return new Boolean(value_);
   }

   public boolean isTrue()
   {
      return value_;
   }

   public void setTrue(boolean b)
   {
      value_ = b;
   }

   public int getTag()
   {
      return ASN1.TAG_BOOLEAN;
   }

   public void encode(Encoder enc)
      throws IOException
   {
      enc.writeBoolean(this);
   }

   public void decode(Decoder dec)
      throws IOException
   {
      dec.readBoolean(this);
   }

   public String toString()
   {
      return "BOOLEAN " + value_;
   }


   public ASN1Type copy()
   {
      try { 
         return (ASN1Boolean) super.clone();
      } catch (CloneNotSupportedException e) { 
         // this shouldn't happen, since we are Cloneable
         throw new InternalError();
      }
   }
}





