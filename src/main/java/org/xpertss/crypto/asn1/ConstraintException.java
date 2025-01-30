package org.xpertss.crypto.asn1;

/**
 * Thrown by {@link Constraint Constraint} instances if the 
 * validation of some ASN.1 type fails.
 */
public class ConstraintException extends ASN1Exception {

   public ConstraintException()
   {
   }

   public ConstraintException(String message)
   {
      super(message);
   }

}
