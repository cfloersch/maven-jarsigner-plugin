package org.xpertss.crypto.pkcs.pkcs9;

import org.xpertss.crypto.asn1.*;
import org.xpertss.crypto.pkcs.PKCSRegistry;

import java.io.IOException;
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

   private Map<ASN1ObjectIdentifier,Attribute> attributes = new LinkedHashMap<>();

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
      this.registry = (registry != null) ? registry
                     : PKCSRegistry.getDefaultRegistry();
   }





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
      return attributes.get(oid);
   }


   /**
    * Returns <code>true</code> if an attribute of the given type exists in this instance.
    *
    * @param oid The type of the attribute.
    * @return <code>true</code> if an attribute with the given OID exists.
    */
   public boolean containsAttribute(ASN1ObjectIdentifier oid)
   {
      return attributes.containsKey(oid);
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
    * This will add the given attribute if, and only if, an attribute with
    * the given OID does not already exist in the sequence.
    *
    * @param attr The attribute to add
    */
   public void addAttribute(Attribute attr)
   {
      if(attributes.putIfAbsent(attr.getOID(), attr) == null) {
         super.add(attr);
      }
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

   @Override
   public void decode(Decoder dec)
           throws IOException
   {
      super.decode(dec);
      for (Iterator<ASN1Type> i = iterator(); i.hasNext();) {
         Attribute attribute = (Attribute) i.next();
         attributes.put(attribute.getOID(), attribute);
      }

   }

}









