package org.xpertss.crypto.asn1;


/**
 * This class represents an ASN.1 UTF 8 String as described
 * in ITU-T Recommendation X.680.
 */
public class ASN1UTF8String extends ASN1AbstractString {

   /**
    * Creates an instance.
    */
   public ASN1UTF8String()
   {
      super();
   }


   public ASN1UTF8String(boolean optional, boolean explicit)
   {
      super(optional, explicit);
   }


   /**
    * Creates an instance with the given string value.
    * No constraints can be set yet so none are checked.
    *
    * @param s - The string value.
    */
   public ASN1UTF8String(String s)
   {
      super(s);
   }



   /**
    * Returns the tag of this class.
    *
    * @return The tag.
    */
   public int getTag()
   {
      return ASN1.TAG_UTF8STRING;
   }
}
