package org.xpertss.crypto.asn1;

import java.io.FilterOutputStream;
import java.io.OutputStream;
import java.io.IOException;


/**
 * Base class for Encoders which can encode ASN objects. The 
 * traditional encoders include BER (Basic Encoding Rules), 
 * DER (Distinguished Encoding Rules), PER (Packed Encoding Rules),
 * etc.
 */
public abstract class AbstractEncoder extends FilterOutputStream implements Encoder {

   /**
    * Creates an encoder that writes its output to the
    * given output stream.
    *
    * @param out The output stream to which the encoded ASN.1
    *   objects are written.
    */
   public AbstractEncoder(OutputStream out)
   {
      super(out);
   }


   /**
    *
    */
   public void writeType(ASN1Type t)
      throws IOException
   {
      t.encode(this);
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
      int b,i;

      b = cls & ASN1.CLASS_MASK;

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
            i = (significantBits(len) + 7) / 8;
            out.write(i | 0x80);
            writeBase256(len);
         } else
            out.write(len);
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
    * Writes the given long to the output in high byte
    * order. It only outputs the minimal number of bytes
    * necessary to represent the value specified by len.
    *
    * @param len The number of bytes necessary to represent this number.
    * @param n The number to be written to the output.
    * @exception IOException Thrown by the underlying
    *   output stream.
    */
   protected void writeInt(byte len, long n)
      throws IOException
   {
      do {
          write((int)((n >> --len * 8) & 0xff));
      } while(len > 0);
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
