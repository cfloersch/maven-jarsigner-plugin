package org.xpertss.crypto.asn1;

import java.io.IOException;


/**
 * The basic interface for Java objects representing primitive 
 * ASN.1 types according to ITU-T Recommendation X.680.
 */
public abstract class ASN1AbstractType implements ASN1Type, Cloneable {

   private boolean optional_ = false;
   private boolean explicit_ = true;
   private Constraint constraint_;

/* Abstract method declarations.
 */

   public abstract Object getValue();

   public abstract int getTag();

   public abstract void encode(Encoder enc)
      throws IOException;

   public abstract void decode(Decoder dec)
      throws IOException;

   public abstract ASN1Type copy();

   
/* Method declarations with default implementation.
 */

   public ASN1AbstractType()
   {
      super();
   }

   public ASN1AbstractType(boolean optional, boolean explicit)
   {
      super();
      optional_ = optional;
      explicit_ = explicit;
   }



   /**
    * Optional types may be present in an encoding but they
    * need not be.
    *
    * @param optional <code>true</code> iff this type is
    *   optional.
    */
   public void setOptional(boolean optional)
   {
      optional_ = optional;
   }


   /**
    * @return <code>true</code> iff this type is optional.
    */
   public boolean isOptional()
   {
      return optional_;
   }



   /**
    * This default implementation returns {@link
    * ASN1#CLASS_UNIVERSAL UNIVERSAL}.
    *
    * @return The class of the ASN.1 tag.
    */
   public int getTagClass()
   {
      return ASN1.CLASS_UNIVERSAL;
   }



   /**
    * Sets the tagging of this type as either EXPLICIT or
    * IMPLICIT. The default is EXPLICIT. Encoders skip the
    * encoding of identifier octets for types that are
    * declared as IMPLICIT.
    *
    * @param explicit <code>true</code> if this type shall be
    *   tagged EXPLICIT and <code>false</code> if it shall be
    *   encoded IMPLICIT.
    */
   public void setExplicit(boolean explicit)
   {
      explicit_ = explicit;
   }


   /**
    * Returns code>true</code> if this type is tagged
    * EXPLICIT and <code>false</code> otherwise.
    *
    * @return <code>true</code> if this type is tagged EXPLICIT
    *   and <code>false</code> if it is tagged IMPLICIT.
    */
   public boolean isExplicit()
   {
      return explicit_;
   }


   /**
    * Returns <code>true</code> if the given tag and tag
    * class matches the tag and tag class of this instance.
    * This method is used primarily by decoders and variable
    * types such as {@link ASN1Choice ASN1Choice} and {@link
    * ASN1OpenType ASN1OpenType}. It enables decoders to
    * query a variable type whether a decoded type is
    * accepted.<p>
    *
    * This method provides a default implementation that
    * matches the given tag and tag class against the
    * values returned by {@link #getTag getTag} and {@link
    * #getTagClass getTagClass} respectively.
    *
    * @param tag The tag to compare with.
    * @param tagclass The tag class to compare with.
    * @return <code>true</code> if the given tag and tag class
    *   matches this type and <code>false</code> otherwise.
    */
   public boolean isType(int tag, int tagclass)
   {
      return (getTag() == tag && getTagClass() == tagclass);
   }


   /**
    * Sets the {@link Constraint Constraint} of this type. For
    * instance an ASN.1 INTEGER might be constrained to a certain
    * range such as INTEGER (0..99). <code>null</code> can be
    * passed as a constraint which disables constraint checking.
    *
    * @param constraint The {@link Constraint Constraint} of
    *   this type.
    */
   public void setConstraint(Constraint constraint)
   {
      constraint_ = constraint;
   }


   /**
    * Returns the {@link Constraint Constraint} of this type
    * or <code>null</code> if there is none.
    *
    * @return The Constraint or <code>null</code>.
    */
   public Constraint getConstraint()
   {
      return constraint_;
   }


   /**
    * Checks the constraint on this type if it is set. Otherwise
    * this method returns silently.
    *
    * @exception ConstraintException if this type is not
    *   in the appropriate range of values.
    */
   public void checkConstraints()
      throws ConstraintException
   {
      if (constraint_ != null)
         constraint_.constrain(this);
   }


   public boolean equals(Object obj)
   {
      if(obj instanceof ASN1Type && obj.getClass() == getClass()) {
         ASN1Type o = (ASN1Type) obj;
         return o.getValue().equals(getValue()); 
      }
      return false;
   }

}
