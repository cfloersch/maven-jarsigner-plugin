package org.xpertss.crypto.asn1;


/**
 * This class represents an ASN.1 PrintableString as described
 * in ITU-T Recommendation X.680.
 */
public class ASN1PrintableString extends ASN1AbstractString {

   public ASN1PrintableString()
   {
      super();
   }

   public ASN1PrintableString(boolean optional, boolean explicit)
   {
      super(optional, explicit);
   }


   /**
    * Creates an instance with the given string value.
    * No constraints can be set yet so none are checked.
    *
    * @param s - The string value.
    */
   public ASN1PrintableString(String s)
   {
      super(s);
   }


   public int getTag()
   {
      return ASN1.TAG_PRINTABLESTRING;
   }
}





