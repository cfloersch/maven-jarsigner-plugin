package org.xpertss.crypto.asn1;

import java.io.IOException;
import java.util.Arrays;


/**
 * Represents an ASN.1 BIT STRING type. The corresponding Java
 * type is <code>boolean[]</code>.
 */
public class ASN1BitString extends ASN1AbstractType {

   private static final byte[] DEFAULT_VALUE = new byte[0];

   private static final byte[] MASK = {
      (byte) 0x80, (byte) 0x40, (byte) 0x20, (byte) 0x10,
      (byte) 0x08, (byte) 0x04, (byte) 0x02, (byte) 0x01
   };

   private int zero = -1;
   private int pad = 0;
   private byte[] value = DEFAULT_VALUE;


   public ASN1BitString()
   {
   }

   public ASN1BitString(boolean optional, boolean explicit)
   {
      super(optional, explicit);
   }

   public ASN1BitString(boolean[] b)
   {
      setBits0(b);
   }


   /**
    * Creates an instance with the given contents. This constructor calls {@link
    * #setBits0(byte[],int) setBits0(byte[] b, int pad)}. Use of this constructor
    * copies the given byte array by reference and may cause side effects.
    *
    * @param b The left aligned contents bits.
    * @param pad The number of pad bits.
    */
   public ASN1BitString(byte[] b, int pad)
   {
      setBits0(b, pad);
   }






   /**
    * This method calls {@link #getBits getBits()}.
    *
    * @return The contents bits as a boolean array.
    */
   public Object getValue()
   {
      return getBits();
   }


   /**
    * Returns the contents bits of this instance. No side
    * effects occur when the returned array is modified.
    *
    * @return The contents bits.
    */
   public boolean[] getBits()
   {
      int i;
      int n;

      if (value.length == 0) return new boolean[0];
      boolean[] b = new boolean[value.length * 8 - pad];

      for (n = 0, i = 0; i < b.length; i++) {
         if ((value[n] & MASK[i & 0x07]) != 0) {
            b[i] = true;
         } else {
            b[i] = false;
         }
         if ((i & 0x07) == 0x07) {
            n++;
         }
      }
      return b;
   }


   /**
    * Sets the contents bits of this instance. This
    * method does not cause side effects.
    *
    * @param bits The contents bits that are set.
    */
   public void setBits(boolean[] bits)
      throws ConstraintException
   {
      setBits0(bits);
      checkConstraints();
   }


   /**
    * Sets the contents bits of this instance. This
    * method does not cause side effects.
    *
    * @param bits The contents bits that are set.
    */
   protected void setBits0(boolean[] bits)
   {
      if (bits == null) {
         value = DEFAULT_VALUE;
         pad = 0;
         zero = 1;
         return;
      }
      int i;
      int n;
      byte m;

      byte[] b = new byte[(bits.length + 7) / 8];

      for (m = 0, n = 0, i = 0; i < bits.length; i++) {
         if (bits[i]) {
            m = (byte) (m | MASK[i & 0x07]);
         }
         if ((i & 0x07) == 0x07) {
            b[n++] = m;
            m = 0;
         }
      }
      if ((i & 0x07) != 0) {
         b[n] = m;
      }
      value = b;
      pad = b.length * 8 - bits.length;
      zero = -1;
   }


   /**
    * Sets the bit string from the given byte aray and
    * pad count. Bit 0 is the most significant bit in
    * the first byte of the array and bit <i>n</i> is
    * bit 7-(<i>n</i><code>&amp;0x07</code>) in byte
    * floor(<i>n</i>/8). The length of the bit string
    * is <code>b.length</code>*8-pad. The pad value
    * be in the range of [0..7]. In other words the
    * bits in the byte array are left aligned.<p>
    *
    * The given byte array is copied by reference.
    * Subsequent modification of it can cause side
    * effects.
    *
    * @param b The bits encoded into a byte array.
    * @param pad The number of pad bits after the
    *   actual bits in the array.
    * @exception IllegalArgumentException if the
    *   pad value is out of range.
    */
   public void setBits(byte[] b, int pad)
      throws ConstraintException
   {
      setBits0(b, pad);
      checkConstraints();
   }


   /**
    * Sets the bits and number of trailing pad bits from
    * the given byte array. The given instance is copied
    * by reference. Therefor side effects can occur when
    * the given byte array is modified subsequently.<p>
    *
    * The given <code>pad</code> value must be in the
    * range from 0 to 7.
    *
    * @param b The minimum number of bytes to hold the
    *   left aligned contents bits.
    * @param pad The number of trailing padding bits.
    */
   protected void setBits0(byte[] b, int pad)
   {
      if (pad < 0 || pad > 7)
         throw new IllegalArgumentException("Illegal pad value (" + pad + ")");
      if (b.length == 0 && pad != 0)
         throw new IllegalArgumentException("Zero length bit strings can't have pad bits!");
      this.value = b;
      this.pad = pad;
      this.zero = -1;
   }


   /**
    * Returns the contents octets of this instance. The bits
    * are left aligned. The returned byte array is the one
    * used internally. Modifying it causes side effects.
    *
    * @return The bits left aligned in a byte array.
    */
   public byte[] getBytes()
   {
      return value;
   }


   public int getPadCount()
   {
      return pad;
   }


   public int byteCount()
   {
      return value.length;
   }


   public int bitCount()
   {
      return value.length * 8 - pad;
   }


   /**
    * Returns <code>true</code> if the bit string contains
    * no bits that are 1. Otherwise, <code>false</code> is
    * returned. This method is used by the {@link DEREncoder
    * DEREncoder} in order to determine cases in which
    * special encoding is to be used. If no bits of a BIT
    * STRING are 1 then it is encoded as <tt>0x03 0x01 0x00
    * </tt> even if the BIT STRING has hundreds of bits in
    * length.
    *
    * @return <code>true</code> if all bits are zero.
    */
   public boolean isZero()
   {
      if (value.length == 0) return true;
      if (zero < 0) {
         int m;
         int i;

         for (m = 0, i = 0; i < value.length; i++) {
            m = m | value[i];
         }
         zero = (m == 0) ? 1 : 0;
      }
      return (zero == 1);
   }


   public int getTag()
   {
      return ASN1.TAG_BITSTRING;
   }


   public void encode(Encoder enc)
      throws IOException
   {
      enc.writeBitString(this);
   }


   public void decode(Decoder dec)
      throws IOException
   {
      dec.readBitString(this);
      checkConstraints();
   }


   public String toString()
   {
      boolean[] bits = getBits();
      StringBuffer buf = new StringBuffer(12 + bits.length);

      buf.append("BitString {");

      for (int i = 0; i < bits.length; i++) {
         if (bits[i]) {
            buf.append("1");
         } else {
            buf.append("0");
         }
      }
      buf.append("}");

      return buf.toString();
   }

   public ASN1Type copy()
   {
      try { 
         ASN1BitString v = (ASN1BitString) super.clone();
         v.value = (byte[]) value.clone();
         return v;
      } catch (CloneNotSupportedException e) { 
         // this shouldn't happen, since we are Cloneable
         throw new InternalError();
      }
   }

   public boolean equals(Object obj)
   {
      if(obj instanceof ASN1BitString) {
         ASN1BitString o = (ASN1BitString) obj;
         return Arrays.equals(getBits(), o.getBits());
      }
      return false;
   }


}





