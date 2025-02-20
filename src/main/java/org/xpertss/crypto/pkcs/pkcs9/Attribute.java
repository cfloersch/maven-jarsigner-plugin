package org.xpertss.crypto.pkcs.pkcs9;

import org.xpertss.crypto.asn1.*;
import org.xpertss.crypto.pkcs.PKCSRegistry;

import java.io.*;
import java.util.*;

/**
 * This class represents an <code>Attribute</code> as defined in X.501 standard. The ASN.1
 * definition of this structure is
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
 * <p/>
 * <a name="classTable"><h3>Type/Class Table</h3></a>
 * The following table shows the correspondence between PKCS9 attribute types and value
 * component classes. For types not listed here, its name is the OID in string form, its
 * value is a (single-valued) byte array that is the SET's encoding.
 * <p/>
 * <TABLE BORDER CELLPADDING=8 ALIGN=CENTER>
 *
 * <TR>
 * <TH>Object Identifier</TH>
 * <TH>Attribute Name</TH>
 * <TH>Type</TH>
 * <TH>Value Class</TH>
 * </TR>
 *
 * <TR>
 * <TD>1.2.840.113549.1.9.1</TD>
 * <TD>EmailAddress</TD>
 * <TD>Multi-valued</TD>
 * <TD><code>String[]</code></TD>
 * </TR>
 *
 * <TR>
 * <TD>1.2.840.113549.1.9.2</TD>
 * <TD>UnstructuredName</TD>
 * <TD>Multi-valued</TD>
 * <TD><code>String[]</code></TD>
 * </TR>
 *
 * <TR>
 * <TD>1.2.840.113549.1.9.3</TD>
 * <TD>ContentType</TD>
 * <TD>Single-valued</TD>
 * <TD><code>ObjectIdentifier</code></TD>
 * </TR>
 *
 * <TR>
 * <TD>1.2.840.113549.1.9.4</TD>
 * <TD>MessageDigest</TD>
 * <TD>Single-valued</TD>
 * <TD><code>byte[]</code></TD>
 * </TR>
 *
 * <TR>
 * <TD>1.2.840.113549.1.9.5</TD>
 * <TD>SigningTime</TD>
 * <TD>Single-valued</TD>
 * <TD><code>Date</code></TD>
 * </TR>
 *
 * <TR>
 * <TD>1.2.840.113549.1.9.6</TD>
 * <TD>Countersignature</TD>
 * <TD>Multi-valued</TD>
 * <TD><code>SignerInfo[]</code></TD>
 * </TR>
 *
 * <TR>
 * <TD>1.2.840.113549.1.9.7</TD>
 * <TD>ChallengePassword</TD>
 * <TD>Single-valued</TD>
 * <TD><code>String</code></TD>
 * </TR>
 *
 * <TR>
 * <TD>1.2.840.113549.1.9.8</TD>
 * <TD>UnstructuredAddress</TD>
 * <TD>Single-valued</TD>
 * <TD><code>String</code></TD>
 * </TR>
 *
 * <TR>
 * <TD>1.2.840.113549.1.9.9</TD>
 * <TD>ExtendedCertificateAttributes</TD>
 * <TD>Multi-valued</TD>
 * <TD>(not supported)</TD>
 * </TR>
 *
 * <TR>
 * <TD>1.2.840.113549.1.9.10</TD>
 * <TD>IssuerAndSerialNumber</TD>
 * <TD>Single-valued</TD>
 * <TD>(not supported)</TD>
 * </TR>
 *
 * <TR>
 * <TD>1.2.840.113549.1.9.{11,12}</TD>
 * <TD>RSA DSI proprietary</TD>
 * <TD>Single-valued</TD>
 * <TD>(not supported)</TD>
 * </TR>
 *
 * <TR>
 * <TD>1.2.840.113549.1.9.13</TD>
 * <TD>S/MIME unused assignment</TD>
 * <TD>Single-valued</TD>
 * <TD>(not supported)</TD>
 * </TR>
 *
 * <TR>
 * <TD>1.2.840.113549.1.9.14</TD>
 * <TD>ExtensionRequest</TD>
 * <TD>Single-valued</TD>
 * <TD>CertificateExtensions</TD>
 * </TR>
 *
 * <TR>
 * <TD>1.2.840.113549.1.9.15</TD>
 * <TD>SMIMECapability</TD>
 * <TD>Single-valued</TD>
 * <TD>(not supported)</TD>
 * </TR>
 *
 * <TR>
 * <TD>1.2.840.113549.1.9.16.2.12</TD>
 * <TD>SigningCertificate</TD>
 * <TD>Single-valued</TD>
 * <TD>SigningCertificateInfo</TD>
 * </TR>
 *
 * <TR>
 * <TD>1.2.840.113549.1.9.16.2.14</TD>
 * <TD>SignatureTimestampToken</TD>
 * <TD>Single-valued</TD>
 * <TD>byte[]</TD>
 * </TR>
 *
 * </TABLE>
 */
public class Attribute extends ASN1Sequence implements ASN1RegisteredType {
   /**
    * The Object Identifier specifying the attribute type.
    */
   protected ASN1ObjectIdentifier type;

   /**
    * The List of Attribute values.
    */
   protected ASN1Set values;


   /**
    * Creates an instance ready for parsing. Any type of ASN.1 structure will be accepted as
    * the values of this attribute. An <code>ASN1OpenType</code> is used for this.
    */
   public Attribute()
   {
      this(PKCSRegistry.getDefaultRegistry());
   }


   /**
    * Creates an instance ready for parsing. The given {@link OIDRegistry} is used to resolve
    * the attribute type. If the attribute type cannot be resolved upon decoding then an
    * exception is thrown.
    *
    * @param registry The <code>OIDRegistry</code> to use for resolving attribute value types,
    *                 or <code>null</code> if the global registry shall be used.
    */
   public Attribute(OIDRegistry registry)
   {
      super(2);

      if (registry == null)
         registry = OIDRegistry.getGlobalOIDRegistry();
      type = new ASN1ObjectIdentifier();
      values = new ASN1SetOf(new DefinedByResolver(registry, type));
      add(type);
      add(values);
   }




   /**
    * Creates a new instance that is initialised with the given OID and value. <b>Note:</b>
    * the given values are not cloned or copied, they are used directly. Hence, the given
    * types must not be modified hereafter in order to avoid side effects.
    * <p/>
    * The OID must not be <code>null</code>. The <code>value</code> can be <code>null</code>
    * and is replaced by {@link ASN1Null} in that case.
    *
    * @param oid The OID that identifies the given value.
    * @param value The ASN.1 type.
    */
   public Attribute(ASN1ObjectIdentifier oid, ASN1Type value)
   {
      // TODO maybe an array of values? Generic to make sure they are same type?
      super(2);
      if (oid == null) throw new NullPointerException("Need an OID!");
      if (value == null) value = new ASN1Null();
      type = oid;
      values = new ASN1Set(1);
      values.add(value);
      add(oid);
      add(values);
   }


   /**
    * The arguments passed to this constructor are set up directly for parsing. They are not
    * cloned! The OID of the Attribute is the OID returned by the registered
    * type.
    *
    * @param value The registered ASN.1 type.
    */
   public Attribute(ASN1RegisteredType value)
   {
      // TODO Make this an array? Validate all of same type?
      super(2);

      if (value == null) throw new NullPointerException("Need a value!");
      type = value.getOID();
      if (type == null) {
         throw new NullPointerException("Value does not provide an OID!");
      }
      values = new ASN1Set(1);
      values.add(value);
      add(type);
      add(values);
   }


   /**
    * This method returns the OID of this Attribute.
    *
    * @return The OID
    */
   public ASN1ObjectIdentifier getOID()
   {
      return type;
   }


   /**
    * This method returns an unmodifiable view of the list of values of this Attribute.
    *
    * @return The unmodifiable view of the list of attribute values.
    */
   public List valueList()
   {
      return (List) values.getValue();
   }


   /**
    * returns the number of values in this attribute.
    *
    * @return The number of values.
    */
   public int valueCount()
   {
      return values.size();
   }


   /**
    * Returns the value at the given position where position is between 0 and {@code
    * valueCount()-1}.
    *
    * @return The value at the given position.
    * @exception ArrayIndexOutOfBoundsException if the given position is not within the
    *    bounds of the list of attribute values.
    */
   public ASN1Type valueAt(int index)
   {
      return (ASN1Type) values.get(index);
   }


   /**
    * Decodes this instance. If the internal storage object of attributes is a {@code
    * ASN1SetOf} then that set is transformed into a {@code ASN1Set}, and any {@code
    * ASN1OpenType} instances are stripped away. This makes a number of internal objects
    * available for garbage collection.
    * <p/>
    * Consequently, after decoding this instance contains a set with the pure attribute
    * values.
    *
    * @param dec The decoder to use.
    */
   public void decode(Decoder dec)
      throws IOException, ASN1Exception
   {
      super.decode(dec);
      if (!(values instanceof ASN1SetOf)) return;
      try {
         ArrayList<ASN1Type> list = new ArrayList<>(values.size());
         for (Iterator<ASN1Type> i = values.iterator(); i.hasNext();) {
            ASN1Type o = i.next();
            if (o instanceof ASN1OpenType) {
               o = ((ASN1OpenType) o).getInnerType();
            }
            list.add(o);
         }
         values.clear();
         values.addAll(list.toArray(new ASN1Type[0]));
      } catch (ClassCastException e) {
         throw new ASN1Exception("Unexpected type in SET OF!");
      } catch (NullPointerException e) {
         throw new ASN1Exception("NULL in SET OF!");
      }
   }
}









