package org.xpertss.crypto.asn1;


/**
 * Represents a UniversalString. This string type uses a
 * 4-octet encoding of characters. For more details on
 * strings see {@link ASN1AbstractString ASN1AbstractString}.
 */
public class ASN1UniversalString extends ASN1AbstractString {

   public ASN1UniversalString()
   {
      super();
   }

   public ASN1UniversalString(boolean optional, boolean explicit)
   {
      super(optional, explicit);
   }


   /**
    * Creates an instance with the given string value. No constraints could be set yet
    * so none are checked.
    *
    * This constructor calls {@link #setString setString} to set the string value.
    *
    * @param s - The string value.
    */
   public ASN1UniversalString(String s)
   {
      super(s);
   }




   /**
    * Returns the ASN.1 {@link ASN1#TAG_UNIVERSALSTRING tag} of this type.
    *
    * @return The tag value.
    */
   public int getTag()
   {
      return ASN1.TAG_UNIVERSALSTRING;
   }


   /**
    * Converts the given byte array to a string by reading four 
    * bytes per character from the array and concatenating them 
    * into an Unicode character.
    *
    * @param b The byte array to convert.
    */
   public String convert(byte[] b)
   {
      if (b == null)
         throw new NullPointerException("Cannot convert null array!");

      if ((b.length % 4) != 0)
         throw new IllegalArgumentException("Truncated character encoding!");

      char[] c = new char[b.length / 4];
      for (int i = 0; i < c.length; i++)
         c[i] = (char) ( ((b[i*4] << 24) & 0xff000000) |
                         ((b[i*4 + 1] << 16) & 0xff0000) |
                         ((b[i*4 + 2] << 8) & 0xff00) |
                           (b[i*4 + 3] & 0xff) );

      return String.valueOf(c);
   }


   /**
    * Converts the given string to a byte array where each
    * character is transformed into 4 consecutive bytes.
    *
    * @param s The string to convert.
    */
   public byte[] convert(String s)
   {
      if (s == null)
         throw new NullPointerException("Cannot convert null string!");

      char[] c = s.toCharArray();
      byte[] b = new byte[c.length * 4];

      for (int i = 0; i < c.length; i++) {
         b[i*4] = (byte) ((c[i] >>> 24) & 0xff);
         b[i*4+1] = (byte) ((c[i] >>> 16) & 0xff);
         b[i*4+2] = (byte) ((c[i] >>> 8) & 0xff);
         b[i*4+3] = (byte) (c[i] & 0xff);
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
      return s.length() * 4;
   }

}




