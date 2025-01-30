package org.xpertss.crypto.asn1;

import java.io.IOException;


/**
 * Represents an opaque type. An opaque type merely decodes the tag 
 * and tag class and stores the contents octets in an OCTET STRING. 
 * The opaque type is represented in ASN.1 as
 * <code><blockquote>
 * [UNIVERSAL x] IMPLICIT OCTET STRING
 * </blockquote></code>
 * where <code>x</code> is the tag.<p>
 *
 * The opaque type is comparable to an {@link ASN1OpenType open type} 
 * in that it matches any type (just like the deprecated ANY type) on 
 * decoding. The encoding can be reconstructed easily. This type is 
 * used whenever decoding of a structure should be deferred to a later 
 * point in time. For instance an AlgorithmIdentifier implementation 
 * can use an opaque type in order to decode algorithm parameters. The 
 * encoding of the algorithm parameters is then done by JCA/JCE classes 
 * later on.
 * <p>
 * One drawback of the opaque type is that special handling by the 
 * encoders and decoders is rquired to make it work properly. The 
 * main problem is that the opaque type does not store whether the 
 * underlying type is constructed or primitive. This decision must 
 * be made by the encoder.
 * <p>
 *
 * Due to this limitation the opaque type can be used only for 
 * decoding types of class UNIVERSAL.
 */
public class ASN1Opaque extends ASN1TaggedType {

   /**
    * Creates an instance. On decoding, opaque types pretend
    * to be of a particular type and read the actual type's
    * encoding into an OCTET STRING from which it can be
    * retrieved later.
    *
    */
   public ASN1Opaque()
   {
      super(-1, ASN1.CLASS_UNIVERSAL, new ASN1OctetString(), false);
   }

   /**
    * Creates an instance. On decoding, opaque types pretend
    * to be of a particular type and read the actual type's
    * encoding into an OCTET STRING from which it can be
    * retrieved later.
    *
    * @param optional - The object is optional
    */
   public ASN1Opaque(boolean optional)
   {
      super(-1, ASN1.CLASS_UNIVERSAL, new ASN1OctetString(), false);
      setOptional(optional);
   }

   /**
    * Creates an instance that stores the given encoding.
    * The encoding must be a valid DER encoding as
    * specified in X.690. This constructor uses a {@link
    * DERDecoder DERDecoder} in order to decode the
    * identifier octets in the given encoding.<p>
    *
    * <b>Note:</b> If the given encoding contains the
    * concatenation of multiple encodings then only
    * the first one will be stored. All others will
    * be lost.
    *
    * @param code - The encoded opaque asn object
    * @exception ASN1Exception if the given code cannot be
    *   decoded.
    */
   public ASN1Opaque(byte[] code)
      throws IOException
   {
      super(-1, ASN1.CLASS_UNIVERSAL, new ASN1OctetString(), false);
      AsnUtil.decode(this, code);
   }


   /**
    * Creates an instance with the given type, class, and
    * inner type. <b>Be careful</b>, the given octet string
    * must contain the valid DER encoding of the contents
    * octets of a type that matches the tag and tag class.
    * Otherwise coding exceptions are most probably thrown
    * subsequently.
    *
    * @param tag The ASN.1 tag of the opaque type.
    * @param tagclass The tag class of the opaque type.
    * @param b The DER compliant encoding of the contents
    *   octets of the opaque type.
    * @exception NullPointerException if the given byte array
    *   is <code>null</code>.
    */
   public ASN1Opaque(int tag, int tagclass, byte[] b)
   {
      super(tag, tagclass, new ASN1OctetString((byte[]) b.clone()), false);
   }


   /**
    * Creates an instance with the given type, class, and
    * inner type. <b>Be careful</b>, the given octet string
    * must contain the valid DER encoding of the contents
    * octets of a type that matches the tag and tag class.
    * Otherwise coding exceptions are most probably thrown
    * subsequently.
    *
    * @param tag The ASN.1 tag of the opaque type.
    * @param tagclass The tag class of the opaque type.
    * @param b The DER compliant encoding of the contents
    *   octets of the opaque type.
    * @param optional The objct is optional
    * @exception NullPointerException if the given byte array
    *   is <code>null</code>.
    */
   public ASN1Opaque(int tag, int tagclass, byte[] b, boolean optional)
   {
      super(tag, tagclass, new ASN1OctetString((byte[]) b.clone()), false);
      setOptional(optional);
   }



   /**
    * This method adopts the given tag and tag class if
    * this instance is not yet initialised with a tag
    * or tag class. In that case <code>true</code> is
    * returned.<p>
    *
    * If a tag or tag class is already set then this
    * method calls its super method.
    *
    * @param tag The tag to compare with.
    * @param tagclass The tag class to compare with.
    */
   public boolean isType(int tag, int tagclass)
   {
      if (tagclass != ASN1.CLASS_UNIVERSAL) return false;

      if (getTag() == -1) {
         setTag(tag);
         return true;
      }
      return super.isType(tag, tagclass);
   }


   /**
    * This method is a convenience method in order to
    * encode this type with DER. It uses a {@link
    * DEREncoder DEREncoder} in order to encode this
    * type to a byte array which is returned.<p>
    *
    * @return The DER encoding of this type.
    * @throws IOException If there is an error encoding the object
    */
   public byte[] getEncoded()
      throws IOException
   {
      return AsnUtil.encode(this);
   }


   /**
    * Sets the inner type of this opaque type. The given type
    * must be {@link ASN1OctetString ASN1OctetString} or a
    * ClassCastException is thrown.
    *
    * @param t The type to set as the inner type.
    * @exception NullPointerException if the given type is
    *   <code>null</code>.
    * @exception ClassCastException if the given type is not
    *   an ASN1OctetString.
    */
   public void setInnerType(ASN1Type t)
   {
      super.setInnerType((ASN1OctetString) t);
   }


   /**
    * Returns a copy. The copy is a deep copy of this
    * instance except the constraints. Constraints are
    * copied by reference.
    *
    * @return The copy.
    */
   public ASN1Type copy()
   {
      try {
         ASN1Opaque o = (ASN1Opaque) super.clone();
         ASN1OctetString b = (ASN1OctetString) o.getInnerType();
         if(b != null) o.setInnerType((ASN1OctetString) b.copy());
         return o;
      } catch (CloneNotSupportedException e) {
         throw new Error("Internal, clone support mismatch!");
      }
   }

}




