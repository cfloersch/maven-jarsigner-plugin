package org.xpertss.crypto.asn1;

import java.io.*;
import java.util.*;

/**
 * Encodes ASN.1/DER ASN types according to the rules set forth 
 * in ITU-T Recommendation X.690.
 */
public class DEREncoder extends AbstractEncoder {

   private int[] stack_;
   private int sp_;

   /**
    * This variable has a bit set for each tag that
    * denotes a CONSTRUCTED type.
    */
   private int constructed_ = (
      (1 << ASN1.TAG_SEQUENCE) |
      (1 << ASN1.TAG_SET) |
      (1 << ASN1.TAG_REAL));


   /**
    * Creates an encoder that writes its output to the
    * given output stream.
    *
    * @param out The output stream to which the encoded ASN.1
    *   objects are written.
    */
   public DEREncoder(OutputStream out)
   {
      super(out);
   }


   /**
    * Encodes the identifier and length octets. If there
    * are no known lengths then this method creates and
    * runs a {@link RunLengthEncoder RunLengthEncoder} on
    * the given type in order to establish the length of
    * it and of any contained types. This method must not
    * be called with OPTIONAL types else errors may occur.
    * It is the responsibility of the caller to ascertain
    * this precondition. Only the headers of types that
    * are tagged {@link ASN1Type#isExplicit EXPLICIT} are
    * encoded. If the given type is tagged IMPLICIT then
    * this method simply returns.
    *
    * @param t The type of which the header is encoded.
    * @param primitive <code>true</code> if the encoding
    *   is PRIMITIVE and <code>false</code> if it is
    *   CONSTRUCTED.
    */
   protected void writeHeader(ASN1Type t, boolean primitive)
      throws IOException
   {
      if (!t.isExplicit()) return;

      if (stack_ == null || sp_ == 0) {
         RunLengthEncoder enc = new RunLengthEncoder();
         enc.writeType(t);
         stack_ = enc.getLengthFields();
         sp_ = stack_.length;

         if (sp_ < 1)
            throw new ASN1Exception("Cannot determine length!");
      }
      int length = stack_[--sp_];

      writeHeader(t.getTag(), t.getTagClass(), primitive, length);
   }


   public void writeBoolean(ASN1Boolean t)
      throws IOException
   {
      if (t.isOptional()) return;
      writeHeader(t, true);
      write(t.isTrue() ? 0xff : 0x00);
   }


   public void writeInteger(ASN1Integer t)
      throws IOException
   {
      if (t.isOptional()) return;
      writeHeader(t, true);
      write(t.getBigInteger().toByteArray());
   }


   public void writeBitString(ASN1BitString t)
      throws IOException
   {
      if (t.isOptional()) return;

      writeHeader(t, true);

      if (t.isZero()) {
         write(0);
         return;
      }
      write(t.getPadCount());
      write(t.getBytes());
   }


   public void writeOctetString(ASN1OctetString t)
      throws IOException
   {
      if (t.isOptional()) return;

      writeHeader(t, true);
      write(t.getByteArray());
   }


   public void writeNull(ASN1Null t)
      throws IOException
   {
      if (t.isOptional()) return;
      writeHeader(t, true);
   }


   public void writeObjectIdentifier(ASN1ObjectIdentifier t)
      throws IOException
   {
      if (t.isOptional()) return;
      writeHeader(t, true);

      int[] e = t.getOID();
      if (e.length < 2)
         throw new ASN1Exception("OID must have at least 2 elements!");

      write(e[0] * 40 + e[1]);
      for (int i = 2; i < e.length; i++)
         writeBase128(e[i]);
   }


   public void writeReal(ASN1Real t)
      throws IOException
   {
      if (t.isOptional()) return;
      if(t.getDouble().equals(new Double(0)) == false) {
         if(t.getDouble().doubleValue() == Double.POSITIVE_INFINITY) {
            writeHeader(t, true);
            write(0x40);
         } else if(t.getDouble().doubleValue() == Double.NEGATIVE_INFINITY) {
            writeHeader(t, true);
            write(0x41);
         } else if(t.getDouble().equals(new Double(Double.NaN))) {
            writeHeader(t, true);
            write(0x42);
         } else if(t.getDouble().doubleValue() == -0D) {
            writeHeader(t, true);
            write(0x43);
         } else {
            // We will always use binary base 2 encoding
            t.encodeBinary(this);
         }
      } else {
         writeHeader(t, true);
      }
   }


   public void writeString(ASN1String t)
      throws IOException
   {
      if (t.isOptional()) return;
      writeHeader(t, true);
      write(t.convert(t.getString()));
   }


   public void writeCollection(ASN1Collection t)
      throws IOException
   {
      if (t.isOptional()) return;
      writeHeader(t, false);
      try {
         for (Iterator i = t.iterator(); i.hasNext();)
            writeType((ASN1Type) i.next());
      } catch (ClassCastException e) {
         throw new ASN1Exception("Non-ASN.1 type in collection!");
      }
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

      boolean primitive;
      int tag;

      ASN1Type o = t.getInnerType();

      if (!o.isExplicit()) {
         if (t instanceof ASN1Opaque)
            tag = t.getTag();
         else
            tag = o.getTag();

         primitive = ((constructed_ & (1 << tag)) == 0);
      } else
         primitive = false;

      writeHeader(t, primitive);
      writeType(t.getInnerType());
   }


   public void writeTypeIdentifier(ASN1Type t)
      throws IOException
   {
      throw new UnsupportedOperationException("TypeIdentifier is not yet supported!");
   }


   public void write(byte[] b)
      throws IOException
   {
      out.write(b);
   }


   public void write(byte[] b, int off, int len)
      throws IOException
   {
      out.write(b, off, len);
   }


   /**
    * Writes an arbitrary {@link ASN1Type ASN1Type}. The given
    * type is written only if it is not declared OPTIONAL. The
    * type is written by calling its {@link ASN1Type#encode
    * encode} method with <code>this</code> as the argument.
    * The called emthod then should invoke the appropriate
    * encoder method of the primitive type to which the given
    * type corresponds.
    *
    * @param t The type to write.
    * @exception ASN1Exception if the given type cannot be
    *   encoded.
    * @exception IOException if an I/O error occurs.
    */
   public void writeType(ASN1Type t)
      throws IOException
   {
      if (!t.isOptional()) t.encode(this);
   }


   /**
    * This method encodes identifier and length octets. The
    * given length can be negative in which case 0x80 is
    * written to indicate INDEFINITE LENGTH encoding. Please
    * note that this is appropriate only for a BER encoding
    * or CER encoding (ITU-T Recommenation X.690). Encoders
    * are responsible for writing the end of code octets
    * <code>0x00 0x00</code> after encoding the content octets.
    *
    * @param tag The ASN.1 tag
    * @param cls The ASN.1 tag class.
    * @param prim <code>true</code> if the encoding is
    *   PRIMITIVE and <code>false</code> if it is CONSTRUCTED.
    * @param len The number of content octets or -1 to indicate
    *   INDEFINITE LENGTH encoding.
    */
   protected void writeHeader(int tag, int cls, boolean prim, int len)
      throws IOException
   {
      int b = cls & ASN1.CLASS_MASK;

      if (!prim)
         b = b | ASN1.CONSTRUCTED;

      if (tag > 30) {
         b = b | ASN1.TAG_MASK;
         out.write(b);
         writeBase128(tag);
      } else {
         b = b | tag;
         out.write(b);
      }
      if (len == -1) {
         out.write(0x80);
      } else {
         if (len > 127) {
            int i = (significantBits(len) + 7) / 8;
            out.write(i | 0x80);
            writeBase256(len);
         } else {
            out.write(len);
         }
      }
   }


   /**
    * This method computes the number of octets needed
    * to encode the identifier and length octets of the
    * {@link ASN1Type ASN.1 type} with the given tag
    * and contents length. The given length can be
    * negative in which case INDEFINITE LENGTH encoding
    * is assumed.
    *
    * @return The number of octets required for encoding the
    *   identifier and length octets.
    * @param tag The ASN.1 tag.
    * @param len The number of contents octets of the ASN.1
    *   type with the given tag and length.
    */
   protected int getHeaderLength(int tag, int len)
   {
      int n = 2;
      if (tag > 30)
         n = n + (significantBits(tag) + 6) / 7;

      if (len > 127)
         n = n + (significantBits(len) + 7) / 8;
      return n;
   }


   /**
    * Writes the given integer to the output in base 128
    * representation with bit 7 of all octets except the
    * last one being set to &quot;1&quot;. The minimum
    * number of octets necessary is used.
    *
    * @param n The integer to be written to the output.
    * @exception IOException Thrown by the underlying
    *   output stream.
    */
   protected void writeBase128(int n)
      throws IOException
   {
      int i = (significantBits(n) + 6) / 7;
      int j = (i - 1) * 7;

      while (i > 1) {
         out.write(((n >>> j) & 0x7f) | 0x80);
         j = j - 7;
         i--;
      }
      out.write(n & 0x7f);
   }


   /**
    * Writes the given integer to the output in base
    * 256 with the minimal number of octets.
    *
    * @param n The integer to be written to the output.
    * @exception IOException Thrown by the underlying
    *   output stream.
    */
   protected void writeBase256(int n)
      throws IOException
   {
      int i = (significantBits(n) + 7) / 8;
      int j = (i - 1) * 8;

      while (i > 0) {
         out.write((n >>> j) & 0xff);
         j = j - 8;
         i--;
      }
   }


   /**
    * Counts the number of significant bits in the given
    * integer. There is always at least one significant
    * bit.
    *
    * @param n - The integer.
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
}
