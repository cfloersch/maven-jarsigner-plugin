package org.xpertss.crypto.asn1;


/**
 * Represents an ASN.1 SEQUENCE type as specified in ITU-T
 * Recommendation X.680.
 */
public class ASN1Sequence extends ASN1AbstractCollection {

   public ASN1Sequence()
   {
      super();
   }

   
   public ASN1Sequence(int capacity)
   {
      super(capacity);
   }

   
   public ASN1Sequence(boolean optional, boolean explicit)
   {
      super(optional, explicit);
   }


   public ASN1Sequence(int capacity, boolean optional, boolean explicit)
   {
      super(capacity, optional, explicit);
   }



   
   
   /**
    * Returns the {@link ASN1#TAG_SEQUENCE SEQUENCE} tag.
    *
    * @return The {@link ASN1#TAG_SEQUENCE SEQUENCE} tag.
    */
   public int getTag()
   {
      return ASN1.TAG_SEQUENCE;
   }

}







