package org.xpertss.crypto.asn1;

import java.io.IOException;


/**
 * Represents an ASN.1 tagged type. Tagged types are types that
 * modify the tag of an underlying type. The ASN.1 type classes
 * {@link ASN1#CLASS_CONTEXT CONTEXT}, {@link ASN1#CLASS_PRIVATE
 * PRIVATE}, and {@link ASN1#CLASS_APPLICATION APPLICATION}
 * specify tagged types.
 */
public class ASN1TaggedType extends ASN1AbstractType {

   private int tag;
   private int cls = ASN1.CLASS_CONTEXT;

   private ASN1Type inner;


   /**
    * Creates an instance with the given tag, tag class, and
    * inner type. The tagging method is EXPLICIT if <code>
    * explicit</code> is <code>true</code> and IMPLICIT
    * otherwise.
    *
    * @param tag The tag of this type.
    * @param cls The tag class of this type, for instance CONTEXT SPECIFIC.
    * @param inner The inner type of this tagged type.
    * @param explicit <code>true</code> if EXPLICIT tagging
    *   shall be used and <code>false</code> if the tagging
    *   method shall be IMPLICIT.
    * @exception NullPointerException if the given inner
    *   type is <code>null</code>.
    */
   public ASN1TaggedType(int tag, int cls, ASN1Type inner, boolean explicit)
   {
      setTag(tag);
      setTagClass(cls);
      setInnerType(inner);
      this.inner.setExplicit(explicit);
   }


   /**
    * Creates an instance with the given tag and
    * inner type. The tagging method is EXPLICIT if <code>
    * explicit</code> is <code>true</code> and IMPLICIT
    * otherwise. The tag class is set to CONTEXT SPECIFIC.
    *
    * @param tag The tag of this type.
    * @param inner The inner type of this tagged type.
    * @param explicit <code>true</code> if EXPLICIT tagging
    *   shall be used and <code>false</code> if the tagging
    *   method shall be IMPLICIT.
    * @exception NullPointerException if the given inner
    *   type is <code>null</code>.
    */
   public ASN1TaggedType(int tag, ASN1Type inner, boolean explicit)
   {
      setTag(tag);
      setTagClass(ASN1.CLASS_CONTEXT);
      setInnerType(inner);
      this.inner.setExplicit(explicit);
   }


   /**
    * Creates an instance with the given tag, tag class, and
    * inner type. The tagging method is EXPLICIT if <code>
    * explicit</code> is <code>true</code> and IMPLICIT
    * otherwise. The tag class is set to CONTEXT SPECIFIC.
    * If <code>optional</code> is <code>true</code> then this
    * type is declared OPTIONAL.
    *
    * @param tag The tag of this type.
    * @param inner The inner type of this tagged type.
    * @param explicit <code>true</code> if EXPLICIT tagging
    *   shall be used and <code>false</code> if the tagging
    *   method shall be IMPLICIT.
    * @param optional <code>true</code> declares this type
    *   as OPTIONAL.
    * @exception NullPointerException if the given inner
    *   type is <code>null</code>.
    */
   public ASN1TaggedType(int tag, ASN1Type inner, boolean explicit, boolean optional)
   {
      setTag(tag);
      setTagClass(ASN1.CLASS_CONTEXT);
      setInnerType(inner);
      this.inner.setExplicit(explicit);
      setOptional(optional);
   }


   /**
    * Returns the underlying ASN.1 type. Please note that
    * OPTIONAL modifiers of (for instance) context-specific
    * types in compound ASN.1 types refer to the outer type
    * and not to the inner type. Types are declared OPTIONAL
    * by calling their {@link ASN1Type#setOptional setOptional}
    * method.
    *
    * @return The underlying ASN.1 type.
    */
   public ASN1Type getInnerType()
   {
      return inner;
   }


   /**
    * Returns the value of the inner type. The default inner
    * type is {@link ASN1Null ASN1Null}. This method calls
    * {@link ASN1Type#getValue getValue} on the inner type
    * and returns the result.
    *
    * @return The value of the inner type.
    */
   public Object getValue()
   {
      return inner.getValue();
   }


   /**
    * Sets the inner type of this CONTEXT SPECIFIC type.
    *
    * @param t The type to set as the inner type.
    * @exception NullPointerException if the given type is
    *   <code>null</code>.
    */
   public void setInnerType(ASN1Type t)
   {
      if (t == null)
         throw new NullPointerException("Type is NULL!");

      inner = t;
   }


   /**
    * Sets the tag of this type.
    *
    * @param tag The tag.
    */
   public void setTag(int tag)
   {
      this.tag = tag;
   }

   /**
    * Returns the tag of this type.
    *
    * @return The tag of this type.
    */
   public int getTag()
   {
      return tag;
   }


   /**
    * Sets the tag class of this type. This tag class may be one of
    * UNIVERSAL, CONTEXT SPECIFIC, PRIVATE, or APPLICATION.
    *
    * @param cls - The tag class.
    */
   public void setTagClass(int cls)
   {
      this.cls = cls;
   }


   /**
    * Returns the tag class of this type. The default class of this instance is
    * CONTEXT SPECIFIC.
    *
    * @return The class of this ASN.1 tag.
    */
   public int getTagClass()
   {
      return cls;
   }


   /**
    * Tagged types themselves are always tagged EXPLICIT. The inner type can be
    * tagged either EXPLICIT or IMPLICIT. IMPLICIT types are isomorphic to the
    * underlying type except that the tag and tag class is distinct (with regard
    * to encoding).
    *
    * @return <code>true</code>, tagged types themselves are always tagged EXPLICIT.
    */
   public boolean isExplicit()
   {
      return true;
   }


   /**
    * Throws an exception if the give tagging type is not
    * EXPLICIT (<code>true</code>). Tagged types themselves
    * are always EXPLICIT; re-tagging tagged types is <b>
    * very</b> bad style!
    *
    * @param explicit The tagging method of the tagged
    *   (outer) type. This should not be mixed with the
    *   tagging method of the inner type which can be
    *   tagged either EXPLICIT or IMPLICIT.
    */
   public void setExplicit(boolean explicit)
   {
      if (!explicit)
         throw new IllegalArgumentException("Tagged types are never IMPLICIT!");
   }




   public void encode(Encoder enc)
      throws IOException
   {
      enc.writeTaggedType(this);
   }


   public void decode(Decoder dec)
      throws IOException
   {
      dec.readTaggedType(this);
   }


   public String toString()
   {
      StringBuffer buf = new StringBuffer();
      buf.append("[");

      switch (cls) {
         case ASN1.CLASS_CONTEXT:
            buf.append("CONTEXT SPECIFIC ");
            break;
         case ASN1.CLASS_UNIVERSAL:
            buf.append("UNIVERSAL ");
            break;
         case ASN1.CLASS_APPLICATION:
            buf.append("APPLICATION ");
            break;
         case ASN1.CLASS_PRIVATE:
            buf.append("PRIVATE ");
            break;
      }
      buf.append(tag).append("] ");

      if (inner.isExplicit())
         buf.append("EXPLICIT ");
      else
         buf.append("IMPLICIT ");

      buf.append(inner.toString());
      return buf.toString();
   }

   public ASN1Type copy()
   {
      try { 
         ASN1TaggedType v = (ASN1TaggedType) super.clone();
         v.inner = inner.copy();
         return v;
      } catch (CloneNotSupportedException e) { 
         // this shouldn't happen, since we are Cloneable
         throw new InternalError();
      }
   }

}




