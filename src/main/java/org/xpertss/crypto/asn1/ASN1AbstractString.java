package org.xpertss.crypto.asn1;

import java.io.IOException;


/**
 * The root class of all ASN.1 string types including but not 
 * limited to IA5String, VisibleString, PrintableString, UTCTime, 
 * and GeneralizedTime.
 * <p>
 * Each string type is encoded as if it is declared as 
 * <tt>[UNIVERSAL </tt> <i>x</i><tt>] IMPLICIT OCTET STRING</tt> 
 * where <i>x</i> is the tag number of the respective string type 
 * (see ITU-T Rec. X.690, paragraph 8.20.3).
 * <p>
 * There are 8 restructed string types of which 4 do not allow 
 * escape sequences, namely NumericString, PrintableString, 
 * VisibleString (ISO646String) and IA5String. TeletexString 
 * (T61String), VideotextString, GraphicString, and GeneralString
 * allow the use of escape sequences. However, the srings must be 
 * encoded such as to use the minimum number of octets possible. 
 * All these strings use 1-octet representations; IA5String uses 
 * 2-octet representations for special characters.
 * <p>
 * Two unrestricted string types are defined in X.680, namely 
 * BMPString and UniversalString. BMPString uses a 2-octet 
 * representation per character and UniversalString uses a 
 * 4-octet representation.
 * <p>
 * Each string type represented in this package handles octets 
 * to character and character to octets conversion according to 
 * the general coding scheme of the particular string, but not 
 * neccessarily restriction to a particular character set. This 
 * is to be implemented through {@link Constraint constraints} 
 * that are added to the respective types on creation (in the 
 * constructors). Restriction of character sets is thus done on 
 * the Unicode character set used by Java.
 * <p>
 * This class implements plain 1-octet to character conversion 
 * by default. Class {@link ASN1BMPString ASN1BMPString} handles 
 * 2-octet conversion and class {@link ASN1UniversalString
 * ASN1UniversalString} handles 4-octets conversion. Without 
 * reference to ISO defined character encodings these 
 * implementations assume that the <i>n</i>-octet tuples represent 
 * the least significant bits of the Unicode characters with the 
 * corresponding bits set to zero.
 */
public abstract class ASN1AbstractString extends ASN1AbstractType implements ASN1String {

   private static final String DEFAULT_VALUE = "";

   private String value = DEFAULT_VALUE;


   public ASN1AbstractString()
   {
      super();
   }

   public ASN1AbstractString(boolean optional, boolean explicit)
   {
      super(optional, explicit);
   }


   /**
    * Creates an instance with the given string value.
    *
    * This constructor calls {@link #setString setString} to set the string value.
    *
    * @param s - The string value.
    */
   public ASN1AbstractString(String s)
   {
      setString0(s);
   }


   /**
    * Returns the represented string value.
    *
    * @return The string value of this type.
    */
   public Object getValue()
   {
      return value;
   }

   /**
    * Returns the represented string value.
    *
    * @return The string value of this type.
    */
   public String getString()
   {
      return value;
   }


   /**
    * Sets the string value.
    *
    * @param s The string value.
    * @exception ConstraintException if the given string
    *   does not match the constraint set for this
    *   instance.
    */
   public void setString(String s)
      throws ConstraintException
   {
      setString0(s);
      checkConstraints();
   }


   protected void setString0(String s)
   {
      if (s == null) throw new NullPointerException("Need a string!");
      value = s;
   }


   public void encode(Encoder enc)
      throws IOException
   {
      enc.writeString(this);
   }


   public void decode(Decoder enc)
      throws IOException
   {
      enc.readString(this);
      checkConstraints();
   }


   /**
    * Converts the given byte array to a string by filling up each consecutive byte
    * with 0's to the size of the Unicode characters.
    *
    * @param b The byte array to convert.
    */
   public String convert(byte[] b)
   {
      if (b == null)
         throw new NullPointerException("Cannot convert null array!");

      char[] c = new char[b.length];
      for (int i = 0; i < b.length; i++)
         c[i] = (char) (b[i] & 0xff);

      return String.valueOf(c);
   }


   /**
    * Converts the given string to a byte array by chopping
    * away all but the least significant byte of each
    * character.
    *
    * @param s The string to convert.
    */
   public byte[] convert(String s)
   {
      if (s == null)
         throw new NullPointerException("Cannot convert null string!");

      char[] c = s.toCharArray();
      byte[] b = new byte[c.length];

      for (int i = 0; i < c.length; i++)
         b[i] = (byte) (c[i] & 0xff);

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
      return s.length();
   }


   public String toString()
   {
      String s = getClass().getName();
      int n = s.lastIndexOf('.');

      if (n < 0) n = -1;

      s = s.substring(n + 1);
      if (s.startsWith("ASN1"))
         s = s.substring(4);

      return s + " \"" + value + "\"";
   }
   
   
   public ASN1Type copy()
   {
      try { 
         return (ASN1AbstractString) super.clone();
      } catch (CloneNotSupportedException e) { 
         // this shouldn't happen, since we are Cloneable
         throw new InternalError();
      }
   }
   
}




