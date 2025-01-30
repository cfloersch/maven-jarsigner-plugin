package org.xpertss.crypto.asn1;

import java.io.IOException;


/**
 * The basic interface for Java objects representing primitive 
 * ASN.1 types according to ITU-T Recommendation X.680. A special 
 * feature are {@link Constraint constraints}. With constraints 
 * the range of valid values of an ASN.1 type can be limited. 
 * Constraints are validated for most types in the setter methods 
 * allowing initialisation with Java types.
 * <p>
 * An abstract implementation of most of the methods declared in 
 * this interface can be found in {@link ASN1AbstractType 
 * ASN1AbstractType}.
 */
public interface ASN1Type {

   public Object getValue();


   public void setOptional(boolean optional);

   public boolean isOptional();


   public int getTag();

   public int getTagClass();


   public void setExplicit(boolean explicit);

   public boolean isExplicit();


   /**
    * Returns <code>true</code> if this type matches the
    * given tag and tagclass. This method is primarily
    * used by decoders in order to verify the tag and
    * tag class of a decoded type. Basic types need not
    * implement this method since {@link ASN1AbstractType
    * ASN1AbstractType} provides a default implementation.
    * Certain variable types such as {@link ASN1Choice
    * ASN1Choice} and {@link ASN1OpenType ASN1OpenType}
    * implement this method. This helps decoders to
    * determine if a decoded type matches a given ASN.1
    * structure.
    *
    * @param tag The tag to match.
    * @param tagclass The tag class to match.
    * @return <code>true</code> if this type matches the
    *   given tag and tag class.
    */
   public boolean isType(int tag, int tagclass);


   public void encode(Encoder enc)
      throws IOException;

   public void decode(Decoder dec)
      throws IOException;


   /**
    * Sets a {@link Constraint constraint} for this type.
    * Constraints are checked by setter methods and as the
    * last operation of a call to the {@link ASN1Type#decode
    * decode()} method.
    *
    * A number of constraints can be defined in ASN.1;
    * one example is the SIZE constraint on string types.
    * For instance, <tt>foo IA5String (SIZE 10..20)</tt>
    * means the string <tt>foo</tt> can be 10 to 20
    * characters long. Strings can also be constrained
    * with regard to the character sets. The constraint
    * model of this package allows to add arbitrary
    * constraints on types.<p>
    *
    * @param o The constraint to set.
    */
   public void setConstraint(Constraint o);


   /**
    * Returns the {@link Constraint Constraint} of this type
    * or <code>null</code> if there is none.
    *
    * @return The Constraint or <code>null</code>.
    */
   public Constraint getConstraint();


   /**
    * Checks the {@link Constraint constraints} registered
    * with this instance.
    *
    * @see Constraint
    * @see ConstraintCollection
    */
   public void checkConstraints() throws ConstraintException;

   
   /**
    * Create a copy of the ASN1Type. This is almost exactly like
    * the clone operation. However, clone creates only a shallow
    * copy of the object. This method creates a deep copy of the
    * object.
    */
   public ASN1Type copy();
}
