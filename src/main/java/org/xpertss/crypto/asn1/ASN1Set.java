package org.xpertss.crypto.asn1;


/**
 * Represents an ASN.1 SET type as specified in ITU-T
 * Recommendation X.680.<p>
 *
 * This implementation does not sort the elements according
 * to their encodings as required (in principle) by the
 * standard. Upon decoding, all decoded elements are kept
 * in the order they appeared in the encoded stream.
 */
public class ASN1Set extends ASN1AbstractCollection {

   public ASN1Set()
   {
      super();
   }

   public ASN1Set(int capacity)
   {
      super(capacity);
   }

   public ASN1Set(boolean optional, boolean explicit)
   {
      super(optional, explicit);
   }


   public ASN1Set(int capacity, boolean optional, boolean explicit)
   {
      super(capacity, optional, explicit);
   }



   /**
    * Returns the {@link ASN1#TAG_SET SET} tag.
    *
    * @return The {@link ASN1#TAG_SET SET} tag.
    */
   public int getTag()
   {
      return ASN1.TAG_SET;
   }

}







