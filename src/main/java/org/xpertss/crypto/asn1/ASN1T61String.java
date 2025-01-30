package org.xpertss.crypto.asn1;


/**
 * This class represents an ASN.1 T61String as described 
 * in ITU-T Recommendation X.680. Note that no value 
 * checking is performed!
 */
public class ASN1T61String extends ASN1AbstractString {
   /**
    * Constructor.
    */
   public ASN1T61String()
   {
      super();
   }

   public ASN1T61String(boolean optional, boolean explicit)
   {
      super(optional, explicit);
   }

   /**
    * Creates an instance with the given string value.
    * No constraints can be set yet so none are checked.
    *
    * @param s - The string value.
    */
   public ASN1T61String(String s)
   {
      super(s);
   }


   /**
    * Returns the ASN.1 tag of this type.
    *
    * @return The ASN.1 {@link ASN1#TAG_T61STRING tag}.
    */
   public int getTag()
   {
      return ASN1.TAG_T61STRING;
   }
}
