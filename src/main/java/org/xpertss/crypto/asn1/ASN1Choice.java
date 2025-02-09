package org.xpertss.crypto.asn1;

import java.util.ArrayList;
import java.util.Iterator;
import java.io.IOException;


/**
 * This type represents the ASN.1 CHOICE type as specified in ITU-T
 * Recommendation X.680. On decoding, the decoder must be able to
 * decide umambiguously which alternative choice it has to decode.
 * For this reason all elements in a CHOICE type must have distinctive
 * tags.
 * <p/>
 * This class does not enforce the distinctive tag rule. Instead, the
 * alternative with the first matching tag should be chosen by decoders.
 * The application that builds the CHOICE type must take care not to
 * produce ambiguous sets of alternatives.
 * <p/>
 * This class distinguishes alternative choices and an inner type. Upon
 * decoding, the inner type is selected from the list of choices based on
 * the identifier octets encountered in the encoded stream. This type is
 * then {@link #setInnerType set as the inner type} of this instance.
 * Unless an inner type is set (either explicitly or by means of decoding)
 * the state of the choice is undefined.
 * <p/>
 * This instance always mimicks its inner type. The methods
 * {@link ASN1Type#getTag getTag}, {@link ASN1Type#getTagClass getTagClass},
 * {@link ASN1Type#getValue getValue} all return the appropriate results of
 * the corresponding method of the inner type. On encoding an instance of
 * this class the inner type is encoded.
 * <p/>
 * No nested CHOICE classes are supported. In principle this is easily
 * supported but it is not good style to build such structures.
 */
public class ASN1Choice extends ASN1AbstractType {

   private static final String NO_INNER = "No inner type defined!";

   private ASN1Type inner;
   private ArrayList<ASN1Type> choices;


   /**
    * Creates an instance with an initial capacity of 2.
    */
   public ASN1Choice()
   {
      choices = new ArrayList<>(2);
   }


   public ASN1Choice(boolean optional)
   {
      super(optional, true);
      choices = new ArrayList<>(2);
   }


   /**
    * Creates an instance with the given initial capacity. The capacity determines
    * the number of choices to store. This instance is backed by an ArrayList, hence
    * the capacity is increased dynamically as required. Use the trim method to trim
    * the internal list to the number of stored choices in order to reclaim memory.
    *
    * @param capacity The initial capacity for storing choices.
    * @exception IllegalArgumentException if the capacity is less than 1.
    */
   public ASN1Choice(int capacity)
   {
      if (capacity < 1)
         throw new IllegalArgumentException("capacity must be greater than zero!");
      choices = new ArrayList<>(capacity);
   }

   public ASN1Choice(int capacity, boolean optional)
   {
      super(optional, true);
      if (capacity < 1)
         throw new IllegalArgumentException("capacity must be greater than zero!");
      choices = new ArrayList<>(capacity);
   }



   /**
    * Adds the given type as an alternative choice to the collection of
    * choices. The caller has to take care that no ambiguous choices are
    * added. Each added type must have a distinctive tag.
    * <p/>
    * CHOICE elements must neither be OPTIONAL nor tagged IMPLICIT. For
    * safety, this method calls {@link ASN1Type#setOptional setOptional}
    * (false) and {@link ASN1Type#setExplicit setExplicit}(true) on the
    * given type. Callers must not alter this setting after adding a type
    * to this choice. However, the CHOICE itself can be declared OPTIONAL.
    *
    * @param t The ASN.1 type to add as a choice.
    * @exception NullPointerException if the given type is <code>null</code>.
    * @exception IllegalArgumentException if the given type is a ASN1Choice
    *    type.
    */
   public void addType(ASN1Type t)
   {
      if (t == null)
         throw new NullPointerException("Choice is null!");
      if (t instanceof ASN1Choice)
         throw new IllegalArgumentException("No nested CHOICE types are allowed!");
      t.setOptional(false);
      t.setExplicit(true);
      choices.add(t);
   }


   /**
    * Returns the choice with the given tag and tagclass if it exists,
    * otherwise <code>null</code> is returned. This method is called by
    * the decoder in order to determine the appropriate type to decode.
    * The returned type is set up as the inner type by the decoder.
    *
    * @param tag The tag of the type encountered in the
    *   encoded stream. The tags of the various primitive
    *   ASN.1 types are defined in class {@link ASN1 ASN1}.
    * @param tagclass The tag class of the type encountered
    *   in the encoded stream. The tag class identifiers
    *   are defined in class {@link ASN1 ASN1}. See for
    *   instance {@link ASN1#CLASS_UNIVERSAL CLASS_UNIVERSAL}.
    * @return The choice with matching tag and tag class or
    *   <code>null</code> if no matching choice is found.
    */
   public ASN1Type getType(int tag, int tagclass)
   {
      for (Iterator<ASN1Type> i = choices.iterator(); i.hasNext();) {
         ASN1Type t = i.next();
         if (t.getTag() != tag) continue;
         if (t.getTagClass() == tagclass) return t;
      }
      return null;
   }


   public boolean isType(int tag, int tagclass)
   {
      return (getType(tag, tagclass) != null);
   }


   /**
    * Trims the internal list of choices to the actual number of choices stored in
    * it.
    */
   public void trimToSize()
   {
      choices.trimToSize();
   }


   /**
    * Clears the internal list of choices. The inner type remains unaffected if it
    * is already set.
    */
   public void clear()
   {
      choices.clear();
   }


   /**
    * Returns the inner ASN.1 type.
    *
    * @return The inner ASN.1 type.
    */
   public ASN1Type getInnerType()
   {
      return inner;
   }


   /**
    * Sets the inner type.
    *
    * @param t The type to set as the inner type.
    * @exception NullPointerException if the given type is {@code null}.
    */
   public void setInnerType(ASN1Type t)
   {
      if (t == null) throw new NullPointerException("No type given!");
      inner = t;
   }


   /**
    * Returns the tag of the inner type.
    *
    * @return The tag of the inner type.
    * @exception IllegalStateException if the inner type is not set.
    */
   public int getTag()
   {
      if (inner == null)
         throw new IllegalStateException(NO_INNER);
      return inner.getTag();
   }


   /**
    * Returns the tag class of the inner type.
    *
    * @return The tag class of the inner type.
    * @exception IllegalStateException if the inner type is not set.
    */
   public int getTagClass()
   {
      if (inner == null)
         throw new IllegalStateException(NO_INNER);
      return inner.getTagClass();
   }


   /**
    * Returns the value of the inner type. The default inner type is {@link ASN1Null}.
    * This method calls {@link ASN1Type#getValue getValue} on the inner type and
    * returns the result.
    *
    * @return The value of the inner type.
    * @exception IllegalStateException if the inner type is not set.
    */
   public Object getValue()
   {
      if (inner == null) throw new IllegalStateException(NO_INNER);
      return inner.getValue();
   }


   /**
    * Sets the tagging of the inner type as either EXPLICIT or IMPLICIT. The default is
    * EXPLICIT. Encoders skip the encoding of identifier octets for types that are
    * declared as IMPLICIT.
    *
    * @param explicit <code>true</code> if this type shall be tagged EXPLICIT and
    *                 <code>false</code> if it shall be encoded IMPLICIT.
    * @exception IllegalStateException if the inner type is not set.
    */
   public void setExplicit(boolean explicit)
   {
      if (!explicit)
         throw new IllegalArgumentException("CHOICE types must be tagged EXPLICIT!");
   }


   /**
    * Returns the tagging of the inner type.
    *
    * @return <code>true</code> if the inner type is tagged EXPLICIT and
    *    <code>false</code> if it is tagged IMPLICIT.
    * @exception IllegalStateException if the inner type is not set.
    */
   public boolean isExplicit()
   {
      return true;
   }


   /**
    * Sets the {@link Constraint} of the inner type. For instance an ASN.1 INTEGER might
    * be constrained to a certain range such as INTEGER (0..99). <code>null</code> can
    * be passed as a constraint which disables constraint checking.
    *
    * @param constraint The {@link Constraint} of this type.
    * @exception IllegalStateException if the inner type is not set.
    */
   public void setConstraint(Constraint constraint)
   {
      if (inner == null) throw new IllegalStateException(NO_INNER);
      inner.setConstraint(constraint);
   }


   /**
    * Checks the constraint on the inner type if it is set. Otherwise, this method
    * returns silently.
    *
    * @exception ConstraintException if this type is not in the appropriate range
    *    of values.
    * @exception IllegalStateException if the inner type is not set.
    */
   public void checkConstraints()
      throws ConstraintException
   {
      if (inner == null) throw new IllegalStateException(NO_INNER);
      inner.checkConstraints();
   }


   /**
    * Encodes this type to the given encoder. Before this method is called,
    * the inner type must be set. Otherwise an IllegalStateException is
    * thrown.
    * <p>
    * If this method is declared OPTIONAL then still an exception is thrown.
    * The OPTIONAL flag is checked only by {@link Encoder encoders} and
    * {@link Decoder decoders}. Transparent handling of CHOICE types can be
    * achieved by calling <code>{@link Encoder#writeType writeType}
    * (ASN1Choice choice)</code> on the encoder. The encoder's method checks
    * if its argument is OPTIONAL.
    *
    * @param enc The {@link Encoder Encoder} to use for encoding.
    * @exception IllegalStateException if the inner type is not set.
    */
   public void encode(Encoder enc)
      throws IOException
   {
      if (inner == null)
         throw new IllegalStateException(NO_INNER);
      enc.writeType(inner);
   }


   /**
    * Decodes the inner type to the given {@link Decoder decoder}.
    *
    * @param dec The decoder to decode to.
    * @exception IllegalStateException if the open type cannot be resolved on runtime.
    */
   public void decode(Decoder dec)
      throws IOException
   {
      dec.readChoice(this);
      // TODO Do value checking here rather than in DERDecoder
      checkConstraints();
   }


   /**
    * Returns a string representation of this type.
    *
    * @return The string representation.
    */
   public String toString()
   {
      if (inner == null) return "CHOICE <NOT INITIALISED>";
      return "(CHOICE) " + inner.toString();
   }

   
   
   
   public ASN1Type copy()
   {
      try { 
         ASN1Choice v = (ASN1Choice) super.clone();
         v.choices = new ArrayList<>();
         for(int i = 0; i < choices.size(); i++) {
            ASN1Type e = choices.get(i);
            if(e != null) {
               v.choices.add(e.copy());
            } else {
               v.choices.add(null);
            }
         }
         if(inner != null) v.inner = inner.copy();
         return v;
      } catch (CloneNotSupportedException e) { 
         // this shouldn't happen, since we are Cloneable
         throw new InternalError();
      }
   }


   public boolean equals(Object obj)
   {
      if(obj instanceof ASN1Type && obj.getClass() == getClass()) {
         ASN1Choice o = (ASN1Choice) obj;
         return o.getInnerType().equals(getInnerType());
      }
      return false;
   }


}





