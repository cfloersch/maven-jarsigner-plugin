package org.xpertss.crypto.asn1;


/**
 * Represents a BMPString. This string type uses a 2-octet
 * encoding of characters. For more details on strings see
 * {@link ASN1AbstractString ASN1AbstractString}.
 */
public class ASN1BMPString extends ASN1AbstractString {

   public ASN1BMPString()
   {
      super();
   }

   public ASN1BMPString(boolean optional, boolean explicit)
   {
      super(optional, explicit);
   }


   /**
    * Creates an instance with the given string value.
    * The string value is subject to {@link Constraint
    * constraint} checks.<p>
    *
    * This constructor calls {@link #setString setString}
    * to set the string value.
    *
    * @param s - The string value.
    */
   public ASN1BMPString(String s)
   {
      super(s);
   }




   /**
    * Returns the ASN.1 tag of this type which is <tt>
    * [UNIVERSAL {@link ASN1#TAG_BMPSTRING 30}]</tt>.
    *
    * @return The tag value.
    */
   public int getTag()
   {
      return ASN1.TAG_BMPSTRING;
   }


   /**
    * Converts the given byte array to a string by filling up each consecutive
    * 2-byte-tuple with 0's to the size of the Unicode characters.
    *
    * @param b The byte array to convert.
    */
   public String convert(byte[] b)
   {
      if (b == null)
         throw new NullPointerException("Cannot convert null array!");

      if ((b.length % 2) != 0)  // TODO: Throw an Exception which must be caught???
         throw new IllegalArgumentException("Truncated character encoding!");

      char[] c = new char[b.length / 2];
      for (int i = 0; i < c.length; i++)
         c[i] = (char) (((b[i * 2] << 8) & 0xff) | (b[i * 2 + 1] & 0xff));

      return String.valueOf(c);
   }


   /**
    * Converts the given string to a byte array by chopping
    * away all but the two least significant byte of each
    * character.
    *
    * @param s The string to convert.
    */
   public byte[] convert(String s)
   {
      if (s == null)
         throw new NullPointerException("Cannot convert null string!");

      char[] c = s.toCharArray();
      byte[] b = new byte[c.length * 2];

      for (int i = 0; i < c.length; i++) {
         b[i * 2] = (byte) ((c[i] >>> 8) & 0xff);
         b[i * 2 + 1] = (byte) (c[i] & 0xff);
      }
      return b;
   }

   /**
    * Returns the number of bytes required to store the
    * converted string.
    *
    * @param s The string.

    */
   public int convertedLength(String s)
   {
      return s.length() * 2;
   }
}




