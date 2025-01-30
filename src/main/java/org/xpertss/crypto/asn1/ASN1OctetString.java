package org.xpertss.crypto.asn1;

import java.io.IOException;
import java.util.Arrays;


/**
 * Represents an ASN.1 OCTET STRING type. The corresponding Java
 * type is <code>byte[]</code>.
 */
public class ASN1OctetString extends ASN1AbstractType {

   private static final byte[] DEFAULT_VALUE = new byte[0];

   private byte[] value = DEFAULT_VALUE;

   public ASN1OctetString()
   {
   }

   public ASN1OctetString(boolean optional, boolean explicit)
   {
      super(optional, explicit);
   }


   /**
    * Creates an instance with side effects. The given
    * array is copied by reference.
    *
    * @param b The byte array that is set as contents.
    */
   public ASN1OctetString(byte[] b)
   {
      setByteArray0(b);
   }




   public Object getValue()
   {
      return getByteArray();
   }


   /**
    * Returns the contents octets as a byte array. The returned
    * byte array is is the instance used internally. Do not
    * modify it, otherwise side effects occur.
    *
    * @return The contents octets as a byte array.
    */
   public byte[] getByteArray()
   {
      return (byte[]) value.clone();
   }


   /**
    * Sets the given bytes. The given byte array is copied
    * by reference. Be careful, side effects can occur if the
    * array is modified subsequent to calling this method.
    * Constraints are checked after setting the bytes.
    *
    * @param b The byte array that is set.
    * @exception ConstraintException if the constraint
    *   is not met by the given byte array.
    */
   public void setByteArray(byte[] b)
      throws ConstraintException
   {
      setByteArray0(b);
      checkConstraints();
   }


   /**
    * Sets the given bytes. The given byte array is copied
    * by reference. Be careful, side effects can occur if the
    * array is modified subsequent to calling this method.
    *
    * @param b The byte array that is set.
    */
   private void setByteArray0(byte[] b)
   {
      if (b == null) value = DEFAULT_VALUE;
      else value = b;
   }


   public int byteCount()
   {
      return value.length;
   }


   public int getTag()
   {
      return ASN1.TAG_OCTETSTRING;
   }


   public void encode(Encoder enc)
      throws ASN1Exception, IOException
   {
      enc.writeOctetString(this);
   }


   public void decode(Decoder dec)
      throws IOException
   {
      dec.readOctetString(this);
      checkConstraints();
   }


   public String toString()
   {
      StringBuffer buf = new StringBuffer("Octet String");

      for (int i = 0; i < value.length; i++) {
         String octet = Integer.toHexString(value[i] & 0xff);
         buf.append(' ');
         if (octet.length() == 1) buf.append('0');
         buf.append(octet);
      }
      return buf.toString();
   }


   /**
    * Returns a clone. The clone is a deep copy of this
    * instance with the exception of constraints. Constraints
    * are copied by reference.
    *
    * @return The clone.
    */
   public ASN1Type copy()
   {
      try {
         ASN1OctetString o = (ASN1OctetString) super.clone();
         o.value = (byte[]) value.clone();
         return o;
      } catch (CloneNotSupportedException e) {
         throw new Error("Internal, clone support mismatch!");
      }
   }

   public boolean equals(Object obj)
   {
      if(obj instanceof ASN1OctetString) {
         ASN1OctetString o = (ASN1OctetString) obj;
         return Arrays.equals(o.getByteArray(), getByteArray());
      }
      return false;
   }
}





