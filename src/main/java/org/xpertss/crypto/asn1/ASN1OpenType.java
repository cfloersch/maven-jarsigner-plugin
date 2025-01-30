package org.xpertss.crypto.asn1;

import java.io.*;

/**
 * This type represents what was formerly called the ASN.1 ANY 
 * type. The ANY and ANY DEFINED BY types are superseded as of 
 * ITU-T Recommendation X.680 version current December 1997 by 
 * the ability to define type classes. Modelling type classes 
 * is beyond the scope of this ASN.1 package although the package 
 * can be enhanced accordingly. ASN.1 type classes can contain 
 * components whose type is unspecified. Such components are 
 * called &quot;open types&quot;. This class mimics an open 
 * type insofar as it decodes any type encountered in an encoded 
 * stream of ASN.1 types. On encoding the proper type is encoded 
 * in place of the open type. Decoding an open type that was not 
 * properly initialised either by a call to a creator with an 
 * argument or by decoding it from a valid ASN.1 encoding results 
 * in an {@link ASN1Null ASN1Null} being decoded.
 * <p>
 * This class enforces as an invariant that inner types have the 
 * same tagging as the type itself. For instance:
 * <blockquote><pre>
 * ASN1OpenType ot;
 * ASN1Integer n;
 *
 * n = new ASN1Integer("42");
 * n.setExplicit(true);
 *
 * ot = new ASN1OpenType(new FooResolver());
 * ot.setExplicit(false);
 * ot.setInnerType(n);
 * </pre></blockquote>
 * will cause the tagging method of <code>n</code> to be changed 
 * into EXPLICIT upon the call to <code>ot.setInnerType()</code>.
 */
public class ASN1OpenType extends ASN1AbstractType {

   private static final String NO_INNER = "No inner type defined!";

   private ASN1Type inner;
   protected Resolver resolver;


   public ASN1OpenType()
   {
      super();
   }


   /**
    * Creates an instance that attempts to resolve the
    * actual type on decoding using the given {@link
    * Resolver Resolver}.
    *
    * @param resolver The instance that is asked to deliver
    *   the type to decode.
    */
   public ASN1OpenType(Resolver resolver)
   {
      this.resolver = resolver;
   }


   /**
    * This constructor corresponds to the superseded
    * ANY DEFINED BY type. The open type attempts to
    * resolve the type to decode right before decoding
    * by a call to the given registry with the given
    * OID as the argument. The exact OID instance is
    * used that is passed to this method as the argument.
    * If this instance is decoded before the open type
    * is decoded (because the OID is encountered earlier
    * in a decoded stream) then the open type can determine
    * the exact type to decode by a call to the registry.
    *
    * @param oid The OID that is passed to the given
    *   registry on resolving.
    */
   public ASN1OpenType(OIDRegistry registry, ASN1ObjectIdentifier oid)
   {
      this.resolver = new DefinedByResolver(registry, oid);
   }


   public ASN1OpenType(ASN1ObjectIdentifier oid)
   {
      this.resolver = new DefinedByResolver(oid);
   }


   /**
    * Returns the inner ASN.1 type. If the inner type is
    * not set and a {@link Resolver Resolver} is set then
    * the Resolver is asked to resolve the inner type.
    * The resulting type is then returned.<p>
    *
    * This method may return <code>null</code> if the
    * resolver cannot determine the inner type of the
    * open type. In particular, if the Resolver is
    * <code>null</code> and no inner type is already
    * set then <code>null</code> is returned.
    *
    * @return The inner ASN.1 type.
    */
   public ASN1Type getInnerType()
      throws ResolverException
   {
      if (inner != null) return inner;
      if (resolver == null) return null;
      inner = resolver.resolve(this);
      return inner;
   }


   /**
    * Sets the inner type. The inner type inherits the tagging
    * of this type.
    *
    * @param t The type to set as the inner type.
    * @exception NullPointerException if the given type
    *   is <code>null</code>.
    */
   protected void setInnerType(ASN1Type t)
   {
      inner = t;
      inner.setExplicit(isExplicit());
   }


   /**
    * Returns the tag of the inner type.
    *
    * @return The tag of the inner type.
    * @exception IllegalStateException if the inner type
    *   is not yet initialised.
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
    * @exception IllegalStateException if the inner type
    *   is not yet initialised.
    */
   public int getTagClass()
   {
      if (inner == null)
         throw new IllegalStateException(NO_INNER);
      return inner.getTagClass();
   }


   /**
    * Returns the value of the inner type. The default inner
    * type is {@link ASN1Null ASN1Null}. This method calls
    * {@link ASN1Type#getValue getValue} on the inner type
    * and returns the result.
    *
    * @return The value of the inner type.
    * @exception IllegalStateException if the inner type
    *   is not yet initialised.
    */
   public Object getValue()
   {
      if (inner == null)
         throw new IllegalStateException(NO_INNER);
      return inner.getValue();
   }


   /**
    * Sets the tagging to either EXPLICIT or IMPLICIT.
    * If this type already has an inner type set then
    * the tagging of the inner type is set to the same
    * tagging.
    *
    * @param explicit <code>true</code> if this type shall be
    *   tagged EXPLICIT and <code>false</code> if it shall be
    *   encoded IMPLICIT.
    * @exception IllegalStateException if the inner type
    *   is not yet initialised.
    */
   public void setExplicit(boolean explicit)
   {
      super.setExplicit(explicit);
      if (inner != null) inner.setExplicit(explicit);
   }


   /**
    * Sets the {@link Constraint Constraint} of the inner type.
    * For instance an ASN.1 INTEGER might be constrained to a
    * certain range such as INTEGER (0..99). <code>null</code>
    * can be passed as a constraint which disables constraint
    * checking.
    *
    * @param constraint The {@link Constraint Constraint} of
    *   this type.
    * @exception IllegalStateException if the inner type
    *   is not yet initialised.
    */
   public void setConstraint(Constraint constraint)
   {
      if (inner == null)
         throw new IllegalStateException(NO_INNER);
      inner.setConstraint(constraint);
   }


   /**
    * Checks the constraint on the inner type if it is set.
    * Otherwise this method returns silently.
    *
    * @exception ConstraintException if this type is not
    *   in the appropriate range of values.
    * @exception IllegalStateException if the inner type
    *   is not yet initialised.
    */
   public void checkConstraints()
      throws ConstraintException
   {
      if (inner == null)
         throw new IllegalStateException(NO_INNER);
      inner.checkConstraints();
   }


   /**
    * This method compares the given tag and tag class
    * with the tag and tag class of the resolved type.
    * <p>
    * If an exception is thrown by the {@link Resolver
    * Resolver} upon resolving the inner type of this
    * type then <code>false</code> is returned in
    * order to provoke a decoding error.<p>
    *
    * If no inner type can be resolved then <code>true
    * </code> is returned. In that case this type behaves
    * like the ANY type known from previous ASN.1 versions.
    *
    * @param tag The tag to match.
    * @param tagclass The tag class to match.
    * @return <code>true</code> iff the given tag and
    *   tag class match one of the alternative types
    *   represented by this variable type.
    */
   public boolean isType(int tag, int tagclass)
   {
      if (inner != null)
         return inner.isType(tag, tagclass);
      try {
         if (resolver != null)
            inner = resolver.resolve(this);
      } catch (ResolverException e) {
         return false;
      }

      /* If no inner type could be resolved then we
       * behave like the ANY type.
       */
      return inner == null || inner.isType(tag, tagclass);
   }


   /**
    * Encodes the inner typeof this open type using the
    * given {@link Encoder Encoder}. If the inner type
    * is not yet initialised then an exception is thrown.
    *
    * @param enc The {@link Encoder Encoder} to use for
    *   encoding the inner type.
    * @exception IllegalStateException if the inner type
    *   is not yet initialised.
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
    * If a {@link Resolver resolver} was specified then it is
    * asked to provide an ASN.1 type to decode.
    *
    * @param dec The decoder to decode to.
    * @exception IllegalStateException if the open type
    *   cannot be resolved on runtime.
    */
   public void decode(Decoder dec)
      throws IOException
   {
      if (resolver != null && inner == null)
         inner = resolver.resolve(this);
      if (inner == null) {
         inner = dec.readType();
      } else {
         inner.decode(dec);
      }
      inner.setExplicit(isExplicit());
   }


   /**
    * Returns the string representation of this instance.
    *
    * @return The string representation of this instance.
    */
   public String toString()
   {
      if (inner == null)
         return "Open Type <NOT INITIALISED>";
      return "(Open Type) " + inner.toString();
   }
   
   
   /**
    * Creates a deep copy of this object. However the resolver
    * is copied by reference only.
    */
   public ASN1Type copy()
   {
      try { 
         ASN1OpenType v = (ASN1OpenType) super.clone();
         if(inner != null) v.inner = inner.copy();
         return v;
      } catch (CloneNotSupportedException e) { 
         throw new InternalError();
      }
   }
   
}





