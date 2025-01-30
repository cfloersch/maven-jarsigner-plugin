package org.xpertss.crypto.asn1;


/**
 * The common interface of all ASN.1 string types. This
 * interface specifies setter and getter methods for
 * string values and methods for string to octet and
 * octet to string conversion. See {@link ASN1AbstractString
 * ASN1AbstractString} for details on strings.
 */
public interface ASN1String extends ASN1Type {
   /**
    * Returns the represented string value.
    *
    * @return The string value of this type.
    */
   public String getString();


   /**
    * Sets the string value.
    *
    * @param s The string value.
    */
   public void setString(String s) throws ConstraintException;


   /**
    * Converts the given byte array to a string.
    *
    * @param b The byte array to convert.
    */
   public String convert(byte[] b);


   /**
    * Converts the given string to a byte array.
    *
    * @param s The string to convert.
    */
   public byte[] convert(String s);


   /**
    * Returns the number of octets required to encode the
    * given string according to the basic encoding scheme
    * of this type. For restricted string types this likely
    * equals the number of characters in the string unless
    * special characters or escape sequences are allowed.
    * For {@link ASN1BMPString BMPStrings} this is twice the
    * number of characters and for {@link ASN1UniversalString
    * UniversalStrings} it is four times the number of
    * characters in the string.<p>
    *
    * The number returned must equal the number returned by
    * the method call {@link #convert(java.lang.String)
    * convert(s)}. This method is required for DER encoding
    * of string types in order to determine the number of
    * octets required for encoding the given string. For
    * BER encoding this method is not and the encoding of
    * the string may be broken up into consecutive OCTET
    * STRINGS.
    *
    * @param s The string whose encoding length is determined.
    */
   public int convertedLength(String s);

}




