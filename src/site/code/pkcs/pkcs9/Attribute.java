package org.xpertss.crypto.pkcs.pkcs9;

import org.xpertss.crypto.asn1.*;

import java.io.*;
import java.util.*;

/**
 * This class represents an <code>Attribute</code> as defined in
 * X.501 standard. The ASN.1 definition of this structure is
 * <p>
 * <pre>
 * Attribute ::= SEQUENCE {
 *   type         AttributeType,
 *   values       SET OF AttributeValue
 * }
 *
 * AttributeType ::= ObjectIdentifier
 * AttributeValue ::= ANY
 * </pre>
 */
public class Attribute extends ASN1Sequence implements ASN1RegisteredType {
   /**
    * The Object Identifier specifying the attribute type.
    */
   protected ASN1ObjectIdentifier type_;

   /**
    * The List of Attribute values.
    */
   protected ASN1Set values_;


   /**
    * Creates an instance ready for parsing. Any type of
    * ASN.1 structure will be accepted as the values of
    * this attribute. An <code>ASN1OpenType</code> is
    * used for this.
    */
   public Attribute()
   {
      super(2);
      type_ = new ASN1ObjectIdentifier();
      values_ = new ASN1SetOf(ASN1OpenType.class);
      add(type_);
      add(values_);
   }


   /**
    * Creates an instance ready for parsing. The given
    * {@link OIDRegistry OIDRegistry} is used to resolve
    * the attribute type. If the attribute type cannot be
    * resolved upon decoding then an exception is thrown.
    *
    * @param registry The <code>OIDRegistry</code> to use
    *   for resolving attribute value types, or <code>null
    *   </code> if the global registry shall be used.
    */
   public Attribute(OIDRegistry registry)
   {
      super(2);

      if (registry == null)
         registry = OIDRegistry.getGlobalOIDRegistry();
      type_ = new ASN1ObjectIdentifier();
      values_ = new ASN1SetOf(new DefinedByResolver(registry, type_));
      add(type_);
      add(values_);
   }


   /**
    * Creates a new instance that is initialised with the
    * given OID and value. <b>Note:</b> the given values
    * are not cloned or copied, they are used directly.
    * Hence, the given types must not be modified after
    * hereafter in order to avoid side effects.<p>
    *
    * The OID must not be <code>null</code>. The <code>
    * value</code> can be <code>null</code> and is replaced
    * by {@link ASN1Null ASN1Null} in that case.
    *
    * @param oid The OID that identifies the given value.
    * @param value The ASN.1 type.
    */
   public Attribute(ASN1ObjectIdentifier oid, ASN1Type value)
   {
      super(2);
      if (oid == null) throw new NullPointerException("Need an OID!");
      if (value == null) value = new ASN1Null();
      type_ = oid;
      values_ = new ASN1Set(1);
      values_.add(value);
      add(oid);
      add(values_);
   }


   /**
    * The arguments passed to this constructor are set up
    * directly for parsing. They are not cloned! The OID
    * of the Attribute is the OID returned by the registered
    * type.
    *
    * @param value The registered ASN.1 type.
    */
   public Attribute(ASN1RegisteredType value)
   {
      super(2);

      if (value == null) throw new NullPointerException("Need a value!");
      type_ = value.getOID();
      if (type_ == null) {
         throw new NullPointerException("Value does not provide an OID!");
      }
      values_ = new ASN1Set(1);
      values_.add(value);
      add(type_);
      add(values_);
   }


   /**
    * This method returns the OID of this Attribute.
    *
    * @return The OID
    */
   public ASN1ObjectIdentifier getOID()
   {
      return type_;
   }


   /**
    * This method returns an unmodifiable view of the
    * list of values of this Attribute.
    *
    * @return The unmodifiable view of the list of
    *   attribute values.
    */
   public List valueList()
   {
      return (List) values_.getValue();
   }


   /**
    * returns the number of values in this attribute.
    *
    * @return The number of values.
    */
   public int valueCount()
   {
      return values_.size();
   }


   /**
    * Returns the value at the given position where position
    * is between 0 and <code>valueCount()-1</code>.
    *
    * @return The value at the given position.
    * @exception ArrayIndexOutOfBoundsException if the
    *   given position is not within the bounds of the
    *   list of attribute values.
    */
   public ASN1Type valueAt(int index)
   {
      return (ASN1Type) values_.get(index);
   }


   /**
    * Decodes this instance. If the internal storage object
    * of attributes is a <code>ASN1SetOf</code> then that
    * set is transformed into a <code>ASN1Set</code>, and
    * any <code>ASN1OpenType</code> instances are stripped
    * away. This makes a number of internal objects available
    * for garbage collection.<p>
    *
    * Consequently, after decoding this instance contains a
    * set with the pure attribute values.
    *
    * @param dec The decoder to use.
    */
   public void decode(Decoder dec)
      throws IOException, ASN1Exception
   {
      super.decode(dec);
      if (!(values_ instanceof ASN1SetOf)) return;
      try {
         ArrayList<ASN1Type> list = new ArrayList<>(values_.size());
         for (Iterator<ASN1Type> i = values_.iterator(); i.hasNext();) {
            ASN1Type o = i.next();
            if (o instanceof ASN1OpenType) {
               o = ((ASN1OpenType) o).getInnerType();
            }
            list.add(o);
         }
         values_.clear();
         values_.addAll(list.toArray(new ASN1Type[0]));
      } catch (ClassCastException e) {
         throw new ASN1Exception("Unexpected type in SET OF!");
      } catch (NullPointerException e) {
         throw new ASN1Exception("NULL in SET OF!");
      }
   }
}









