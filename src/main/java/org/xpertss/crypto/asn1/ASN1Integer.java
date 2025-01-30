package org.xpertss.crypto.asn1;

import java.math.BigInteger;
import java.io.IOException;


/**
 * Represents an ASN.1 INTEGER type. The corresponding Java
 * type is java.math.BigInteger.
 */
public class ASN1Integer extends ASN1AbstractType {

   /**
    * The value of this ASN.1 INTEGER.
    */
   private BigInteger value;



   /**
    * Creates a new instance ready for parsing. The value of
    * this instance is set to 0.
    */
   public ASN1Integer()
   {
      value = BigInteger.ZERO;
   }

   public ASN1Integer(boolean optional, boolean explicit)
   {
      super(optional, explicit);
      value = BigInteger.ZERO;
   }

   /**
    * Creates a new instance with the given BigInteger as its
    * initial value.
    *
    * @param val The value.
    */
   public ASN1Integer(BigInteger val)
   {
      if (val == null)
         throw new NullPointerException("Need a number!");

      value = val;
   }


   /**
    * Creates an ASN.1 INTEGER from the given string representation.
    *
    * This method calls the equivalent constructor of class
    * {@link java.math.BigInteger java.math.BigInteger}.
    *
    * @param val The string representation of the multiple
    *   precision integer.
    * @exception NumberFormatException if the string could
    *   not be parsed successfully.
    */
   public ASN1Integer(String val)
      throws NumberFormatException
   {
      value = new BigInteger(val);
   }


   /**
    * Creates a new instance from the given byte array. The
    * byte array contains the two's-complement binary
    * representation of a BigInteger. The input array is
    * assumed to be in <i>big endian</i> byte-order. The
    * most significant byte is in the zeroth element.
    *
    * This method calls the equivalent constructor of class
    * {@link java.math.BigInteger java.math.BigInteger}.
    *
    * @param val The two's-complement input number in big
    *   endian byte-order.
    * @exception NumberFormatException if val is zero bytes
    *   long.
    */
   public ASN1Integer(byte[] val)
      throws NumberFormatException
   {
      value = new BigInteger(val);
   }


   /**
    * Translates the sign-magnitude representation of a BigInteger
    * into an ASN.1 INTEGER. The sign is represented as an integer
    * signum value: -1 for negative, 0 for zero, or 1 for positive.
    * The magnitude is a byte array in big-endian byte-order: the
    * most significant byte is in the zeroth element. A zero-length
    * magnitude array is permissible, and will result in in a
    * BigInteger value of 0, whether signum is -1, 0 or 1.<p>
    *
    * This method calls the equivalent constructor of class
    * {@link java.math.BigInteger java.math.BigInteger}.
    *
    * @param signum signum of the number (-1 for negative, 0 for
    *   zero, 1 for positive).
    * @param magnitude The big endian binary representation of the
    *   magnitude of the number.
    * @exception NumberFormatException signum is not one of the
    *   three legal values (-1, 0, and 1), or signum is 0 and
    *   magnitude contains one or more non-zero bytes.
    */
   public ASN1Integer(int signum, byte[] magnitude)
      throws NumberFormatException
   {
      value = new BigInteger(signum, magnitude);
   }


   /**
    * Creates an instance with the given int value.
    *
    * @param n The integer to initialise with.
    */
   public ASN1Integer(int n)
   {
      byte[] b = new byte[4];
      int m = n;
      for (int i = b.length - 1; i >= 0; i--) {
         b[i] = (byte) (m & 0xff);
         m = m >>> 8;
      }
      value = new BigInteger(b);
   }


   /**
    * Creates an instance with the given long value.
    *
    * @param n The long to initialise with.
    */
   public ASN1Integer(long n)
   {
      byte[] b = new byte[8];
      long m = n;
      for (int i = b.length - 1; i >= 0; i--) {
         b[i] = (byte) (m & 0xff);
         m = m >>> 8;
      }
      value = new BigInteger(b);
   }




   public Object getValue()
   {
      return value;
   }

   public BigInteger getBigInteger()
   {
      return value;
   }

   public void setBigInteger(BigInteger n)
      throws ConstraintException
   {
      value = n;
      checkConstraints();
   }

   public int getTag()
   {
      return ASN1.TAG_INTEGER;
   }

   public void encode(Encoder enc)
      throws IOException
   {
      enc.writeInteger(this);
   }

   public void decode(Decoder dec)
      throws IOException
   {
      dec.readInteger(this);
      checkConstraints();
   }


   public String toString()
   {
      return "Integer " + value.toString();
   }
   
   
   public ASN1Type copy()
   {
      try { 
         return (ASN1Integer) super.clone();
      } catch (CloneNotSupportedException e) { 
         // this shouldn't happen, since we are Cloneable
         throw new InternalError();
      }
   }
   
}





