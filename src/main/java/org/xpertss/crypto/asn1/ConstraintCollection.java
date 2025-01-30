package org.xpertss.crypto.asn1;

import java.util.*;

/**
 * Implements a collection of {@link Constraint constraints} that 
 * can be added to any {@link ASN1Type ASN1Type}. This class is 
 * used by the {@link ASN1AbstractType ASN1AbstractType} in order 
 * to manage multiple constraints. It inherits from ArrayList and 
 * simply calls {@link Constraint#constrain constrain} on all 
 * objects contained in it upon a call to its own constrain method.
 */
public class ConstraintCollection extends ArrayList implements Constraint {

   public ConstraintCollection()
   {
      super();
   }

   /**
    * Creates an instance that is initialised with the
    * given capacity.
    *
    * @param capacity The initial capacity of this List.
    */
   public ConstraintCollection(int capacity)
   {
      super(capacity);
   }


   /**
    * Calls {@link Constraint#constrain constrain} on all
    * objects contained in this list. It is the responsibility
    * of the user to assure that only objects that implement
    * the {@link Constraint Constraint} interface are added
    * to this constraint collection. Non-adherence will cause
    * a ClassCastException being thrown.
    *
    * @param o The caller of the method. This reference is
    *   passed to all subordinate constraints.
    * @exception ConstraintException
    */
   public void constrain(ASN1Type o)
      throws ConstraintException
   {
      for (Iterator i = iterator(); i.hasNext();)
         ((Constraint) i.next()).constrain(o);
   }

   /**
    * Adds a {@link Constraint Constraint} to this list.
    *
    * @param o The Constraint to add.
    */
   public void addConstraint(Constraint o)
   {
      add(o);
   }
}
