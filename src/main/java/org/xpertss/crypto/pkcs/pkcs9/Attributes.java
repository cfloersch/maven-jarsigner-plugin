package org.xpertss.crypto.pkcs.pkcs9;

import org.xpertss.crypto.asn1.*;
import org.xpertss.crypto.pkcs.PKCSRegistry;

import java.util.*;

/**
 * This class represents <code>Attributes</code> as defined in PKCS#6. The ASN.1 definition
 * of this structure is
 * <p>
 * <blockquote><pre>
 * Attributes ::= SET OF Attribute
 * </pre></blockquote>
 *
 * Instances can be initialized with a {@link OIDRegistry} that is used to resolve attribute
 * value types. The type of value of a PKCS#6 Content Type Attribute is for instance
 * <code>OBJECT IDENTIFIER</code>. The OID of this attribute is <code>{ pkcs-9 3}</code>. The
 * OID identifies both the attribute and the attribute value's type.
 * <p/>
 * Please note that when a registry is specified, exceptions are thrown if an attribute is
 * encountered whose type cannot be resolved by that registry or any of the global registries.
 */
public class Attributes extends ASN1SetOf {
   /**
    * The registry that is used to resolve attribute values.
    */
   protected OIDRegistry registry;


   /**
    * Creates an instance ready for parsing. Any type of
    * attribute is accepted.
    */
   public Attributes()
   {
      super(0);
   }


   /**
    * Creates an instance ready for parsing. The given {@link OIDRegistry} is used to resolve
    * the attribute value types. Attributes that cannot be resolved will cause exceptions upon
    * decoding.
    *
    * @param registry The <code>OIDRegistry</code> to use for resolving attribute value types,
    *                 or <code>null</code> if the default PKCS registry shall be used.
    */
   public Attributes(OIDRegistry registry)
   {
      super(0);

      if (registry == null) {
         this.registry = PKCSRegistry.getDefaultRegistry();
         return;
      }
      this.registry = registry;
   }


   // TODO Creator methods for instances to be encoded




   /**
    * Returns the first attribute of the given type that is found in this instance.
    *
    * @param oid The type of the attribute.
    * @return The attribute with the given OID or <code>null</code> if no matching attribute is
    *          found.
    */
   public Attribute getAttribute(ASN1ObjectIdentifier oid)
   {
      if (oid == null) throw new NullPointerException("Need an OID!");
      for (Iterator<ASN1Type> i = iterator(); i.hasNext();) {
         Attribute attribute = (Attribute) i.next();
         if (attribute.getOID().equals(oid))
            return attribute;
      }
      return null;
   }


   /**
    * Returns <code>true</code> if an attribute of the given type exists in this instance. This
    * method calls <code>getAttribute(ASN1ObjectIdentifier)</code>. Do not use it if you want
    * to retrieve the attribute subsequent to this method call anyway.
    *
    * @param oid The type of the attribute.
    * @return <code>true</code> if an attribute with the given OID exists.
    */
   public boolean containsAttribute(ASN1ObjectIdentifier oid)
   {
      return (getAttribute(oid) != null);
   }


   /**
    * Returns the attribute at the given position.
    *
    * @param index The position of the attribute to return.
    * @exception ArrayIndexOutOfBoundsException if the given index is not within the bounds of
    *          the attributes list.
    */
   public Attribute getAttribute(int index)
   {
      return (Attribute) get(index);
   }


   /**
    * Returns <code>Attribute.class</code>.
    *
    * @return <code>Attribute.class</code>
    */
   public Class<?> getElementType()
   {
      return Attribute.class;
   }


   /**
    * Returns a new attribute instance. The new attribute is added to this instance
    * automatically.
    *
    * @return The new attribute, ready to be decoded.
    */
   public ASN1Type newElement()
   {
      Attribute attribute;
      if (registry == null) {
         attribute = new Attribute();
      } else {
         attribute = new Attribute(registry);
      }
      add(attribute);
      return attribute;
   }
}









