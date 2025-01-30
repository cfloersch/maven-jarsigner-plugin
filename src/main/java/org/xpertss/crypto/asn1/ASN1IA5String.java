package org.xpertss.crypto.asn1;


/**
 * This class represents an ASN.1 IA5String as described
 * in ITU-T Recommendation X.680.
 */
public class ASN1IA5String extends ASN1AbstractString {


   /**
    * Constructor declaration.
    *
    */
   public ASN1IA5String()
   {
      super();
   }

   public ASN1IA5String(boolean optional, boolean explicit)
   {
      super(optional, explicit);
   }


   /**
    * Creates an instance with the given string value.
    * No constraints can be set yet so none are checked.
    *
    * @param s - The string value.
    */
   public ASN1IA5String(String s)
   {
      super(s);
   }


   /**
    * Method declaration.
    */
   public int getTag()
   {
      return ASN1.TAG_IA5STRING;
   }


}


