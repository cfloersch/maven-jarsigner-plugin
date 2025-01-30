package org.xpertss.crypto.asn1;

import java.io.*;


/**
 * This encoder makes one pass through the given ASN.1 type and 
 * computes the length of the type encoding according to the DER 
 * (ITU-T Recommendation X.690). The result is an array of integers 
 * with the length of the individual non-optional and non-implicit 
 * type encodings in the reverse order of the order in which the given
 * type is traversed during actual encoding. This array is used by the
 * {@link DEREncoder DEREncoder} when encoding a type.
 */
public class RunLengthEncoder extends Object implements Encoder {

   /**
    * The number of slots by which the internal buffer
    * is incremented if its capacity is eexceeded.
    */
   public static final int INCREMENT = 256;

   private int[] stack_;
   private int tops_;
   private int caps_;

   private int[] acc_;
   private int topa_;
   private int capa_;


   /**
    * Creates an encoder.
    */
   public RunLengthEncoder()
   {
   }


   /**
    * This method brings in the harvest of the encoding
    * procedure. It returns the individual lengths of the
    * DER encodings of the types written to to this encoder.
    * The order of length fields is the reverse order of
    * the pre order parsing of the written types.<p>
    *
    * If this method is called before a type has been
    * encoded then an array of zero length is returned.
    * Only non-optional types are counted thus the zero
    * length array might be returned also when all encoded
    * types were declared optional.
    *
    * @return The lengths fields.
    */
   public int[] getLengthFields()
   {
      if (tops_ == 0) return new int[0];
      int[] res = new int[tops_];
      System.arraycopy(stack_, 0, res, 0, tops_);
      return res;
   }


   /**
    * Encodes the length array of the given type.
    */
   public void writeType(ASN1Type o)
      throws IOException
   {
      o.encode(this);
   }


   /**
    * This method computes the number of octets needed
    * to encode the identifier and length octets of the
    * {@link ASN1Type ASN.1 type} with the given tag
    * and contents length. The length must not be negative
    * else an exception is thrown. Since this encoder is
    * meant to work in conjunction with a {@link DEREncoder
    * DEREncoder} no indefinite length is supported.
    *
    * @return The number of octets required for encoding the
    *   identifier and length octets.
    * @param tag The ASN.1 tag.
    * @param len The number of contents octets of the ASN.1
    *   type with the given tag and length.
    * @exception ASN1Exception if the given length is negative.
    */
   public int getHeaderLength(int tag, int len)
      throws IOException
   {
      if (len < 0)
         throw new ASN1Exception("Length is negative!");

      int n = 2;
      if (tag > 30)
         n = n + (significantBits(tag) + 6) / 7;

      if (len > 127)
         n = n + (significantBits(len) + 7) / 8;

      return n;
   }


   /**
    * Counts the number of significant bits in the given
    * integer. There is always at least one significant
    * bit.
    *
    * @param n The integer.
    * @return The number of significant bits in the
    *   given integer.
    */
   protected int significantBits(int n)
   {
      if (n == 0) return 1;

      int i = 0;
      while (n > 255) {
         n = n >>> 8;
         i += 8;
      }
      while (n > 0) {
         n = n >>> 1;
         i++;
      }
      return i;
   }


   public void writeBoolean(ASN1Boolean t)
      throws IOException
   {
      if (t.isOptional()) return;
      push(t, 1);
   }

   public void writeInteger(ASN1Integer t)
      throws IOException
   {
      if (t.isOptional()) return;
      int n = t.getBigInteger().bitLength() / 8 + 1;
      push(t, n);
   }

   public void writeBitString(ASN1BitString t)
      throws IOException
   {
      if (t.isOptional()) return;
      int n;
      if (t.isZero())
         n = 1;
      else
         n = (t.bitCount() + 7) / 8 + 1;

      push(t, n);
   }

   public void writeOctetString(ASN1OctetString t)
      throws IOException
   {
      if (t.isOptional()) return;
      push(t, t.byteCount());
   }


   public void writeNull(ASN1Null t)
      throws IOException
   {
      if (t.isOptional()) return;
      push(t, 0);
   }


   public void writeObjectIdentifier(ASN1ObjectIdentifier t)
      throws IOException
   {
      if (t.isOptional()) return;

      int n;
      int i;

      int[] e = t.getOID();
      if (e.length < 2)
         throw new ASN1Exception("OID must have at least 2 elements!");

      for (n = 1, i = 2; i < e.length; i++)
         n = n + (significantBits(e[i]) + 6) / 7;

      push(t, n);
   }


   public void writeReal(ASN1Real t)
      throws IOException
   {
      if (t.isOptional()) return;
      if(t.getDouble().equals(new Double(0)) == false) {
         if(t.getDouble().doubleValue() == Double.POSITIVE_INFINITY) {
            push(t, 1);
         } else if(t.getDouble().doubleValue() == Double.NEGATIVE_INFINITY) {
            push(t, 1);
         } else if(t.getDouble().equals(new Double(Double.NaN))) {
            push(t, 1);
         } else if(t.getDouble().doubleValue() == -0D) {
            push(t, 1);
         } else {
            push(t, t.encodedLength());
         }
      } else {
         push(t, 0);
      }
   }


   public void writeString(ASN1String t)
      throws IOException
   {
      if (t.isOptional()) return;
      push(t, t.convertedLength(t.getString()));
   }


   public void writeCollection(ASN1Collection t)
      throws IOException
   {
      if (t.isOptional()) return;
      
      int p;
      int i;

      try {
         for (p = sp(), i = t.size() - 1; i >= 0; i--)
            writeType((ASN1Type) t.get(i));

         push(t, accumulate(p));
      } catch (ClassCastException e) {
         throw new ASN1Exception("Non-ASN.1 type in collection!");
      }
   }


   public void writeCollectionOf(ASN1Collection t)
      throws IOException
   {
      writeCollection(t);
   }


   public void writeTime(ASN1Time t)
      throws IOException
   {
      writeString(t);
   }


   public void writeTaggedType(ASN1TaggedType t)
      throws IOException
   {
      if (t.isOptional()) return;
      int p = sp();
      writeType(t.getInnerType());
      int n = accumulate(p);
      push(t, n);
   }


   public void writeTypeIdentifier(ASN1Type t)
      throws IOException
   {
      throw new UnsupportedOperationException("TypeIdentifier is not yet supported!");
   }


   /**
    * Clears the length array and prepares this encoder for
    * a new run.
    */
   protected void reset()
   {
      tops_ = 0;
      topa_ = 0;
   }


   /**
    * Pushes another length integer onto the internal stacks. The value
    * is pushed both on the running stack as well as on the acc_ accumulator
    * stack. The stacks increase dynamically in size in chunks of {@link
    * #INCREMENT INCREMENT} integers and never shrink in capacity.
    *
    * @param t The ASN.1 type.
    * @param n The integer.
    */
   protected void push(ASN1Type t, int n)
      throws IOException
   {
      if (stack_ == null) {
         stack_ = new int[INCREMENT];
         caps_ = INCREMENT;
         tops_ = 0;
      }
      if (tops_ == stack_.length) {
         int[] stack = new int[stack_.length + INCREMENT];
         System.arraycopy(stack_, 0, stack, 0, stack_.length);
         stack_ = stack;
         caps_ = stack_.length;
      }
      if (acc_ == null) {
         acc_ = new int[INCREMENT];
         capa_ = INCREMENT;
         topa_ = 0;
      }
      if (topa_ == acc_.length) {
         int[] stack = new int[acc_.length + INCREMENT];
         System.arraycopy(acc_, 0, stack, 0, acc_.length);
         acc_ = stack;
         capa_ = acc_.length;
      }
      if (t.isExplicit()) {
         stack_[tops_++] = n;
         acc_[topa_++] = n + getHeaderLength(t.getTag(), n);
      } else
         acc_[topa_++] = n;
   }


   /**
    * Returns the acc_ accumulator stack pointer.
    *
    * @return The accumulator stack pointer.
    */
   protected int sp()
   {
      return topa_;
   }

   /**
    * Accumulates all values on the acc_ accumulator stack from
    * the given position to the top of the stack and returns the
    * result. All accumulated values are popped off the stack.
    *
    * @param pos The position to start from.
    * @exception IllegalStateException if the given position
    *   is atop the top of the stack.
    */
   protected int accumulate(int pos)
   {
      int n;
      int i;

      if (pos > topa_)
         throw new IllegalStateException("Internal error, bad stack pointer!");

      for (n = 0, i = pos; i < topa_; i++)
         n = n + acc_[i];

      topa_ = pos;
      return n;
   }
}
