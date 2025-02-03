package org.xpertss.crypto.pkcs.pkcs7;

import org.xpertss.crypto.asn1.*;
import org.xpertss.crypto.pkcs.PKCSRegistry;

import java.io.*;


/**
 * This class represents a <code>ContentInfo</code> as defined in
 * <a href="http://www.rsa.com/rsalabs/pubs/PKCS/html/pkcs-7.html">PKCS#7</a>.
 * The ASN.1 definition of this structure is
 * <p>
 * <pre>
 * ContentInfo ::= SEQUENCE {
 *   contentType ContentType,
 *   content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
 * }
 * ContentType ::= OBJECT IDENTIFIER
 * </pre>
 * <p>
 * <code>contentType</code> indicates the type of content. PKCS#7 specifies six
 * content types: {@link Data}, {@link SignedData}, {@link EnvelopedData},
 * {@link SignedAndEnvelopedData}, {@link DigestedData} and {@link EncryptedData}.
 * All of these content types have registered OIDs.
 * <p>
 *
 * The <code>ContentInfo</code> is also the general syntax of complete PKCS#7 structure.
 */
public class ContentInfo extends ASN1Sequence {


   public static final ASN1ObjectIdentifier DATA_OID = new ASN1ObjectIdentifier(Data.OID);
   public static final ASN1ObjectIdentifier SIGNED_DATA_OID = new ASN1ObjectIdentifier(SignedData.OID);
   public static final ASN1ObjectIdentifier ENVELOPED_DATA_OID = new ASN1ObjectIdentifier(EnvelopedData.OID);
   public static final ASN1ObjectIdentifier SIGNED_AND_EVENLOPED_DATA_OID = new ASN1ObjectIdentifier(SignedAndEnvelopedData.OID);
   public static final ASN1ObjectIdentifier DIGESTED_DATA_OID = new ASN1ObjectIdentifier(DigestedData.OID);
   public static final ASN1ObjectIdentifier ENCRYPTED_DATA_OID = new ASN1ObjectIdentifier(EncryptedData.OID);


   /**
    * The OID defining the contents of this structure.
    */
   protected ASN1ObjectIdentifier contentType;

   /**
    * The actual content of this structure.
    */
   protected ASN1TaggedType content;


   /**
    * This method creates an instance which is initialised for parsing. The {@link PKCSRegistry}
    * is used for resolving OIDs to PKCS7 structures.
    */
   public ContentInfo()
   {
      this(PKCSRegistry.getDefaultRegistry());
   }


   /**
    * Creates an instance ready for decoding. The given <code>OIDRegistry</code> is used to
    * resolve content types. By default, the {@link PKCSRegistry} is used.
    *
    * @param registry The Object Identifier registry that is used to resolve content types, or
    *                 <code>null</code> if a default registry shall be used.
    */
   public ContentInfo(OIDRegistry registry)
   {
      super(2);
      if (registry == null)
         registry = PKCSRegistry.getDefaultRegistry();
      contentType = new ASN1ObjectIdentifier();
      ASN1OpenType ot = new ASN1OpenType(registry, contentType);
      content = new ASN1TaggedType(0, ot, true, true);

      add(contentType);
      add(content);
   }


   /**
    * This constructor sets the content type to the given OID but leaves the actual content
    * empty. This is a constructor required for instance by the {@link SignedData} type in
    * the case of signing detached signatures. Such signatures require the content type to
    * be {@link Data}, but the actual data must be empty (no identifier, length and contents
    * octets).
    *
    * @param o The OID denoting the content type, most probably the {@link Data} content OID.
    */
   public ContentInfo(ASN1ObjectIdentifier o)
   {
      super(1);
      setContent(o);
   }


   /**
    * This method calls {@link #setContent} with the given ASN.1 type, which builds the tree
    * of ASN.1 objects used for decoding this structure.
    *
    * @param o The PKCS#7 content type to embed in this structure.
    */
   public ContentInfo(ASN1RegisteredType o)
   {
      super(2);
      setContent(o);
   }


   /**
    * Returns the <code>contentType</code> of this structure. This value is defined only if the
    * structure has been decoded successfully, or the content has been set
    * previously.
    *
    * @return The OID describing the <code>contentType</code> of this structure.
    */
   public ASN1ObjectIdentifier getContentType()
   {
      return contentType;
   }


   /**
    * This method returns the actual <code>content</code> of this structure.
    *
    * @return The <code>content</code> or <code>null</code> if no content is available.
    */
   public ASN1Type getContent()
   {
      if (content.isOptional()) return null;
      ASN1Type o = content.getInnerType();
      if (o instanceof ASN1OpenType) return null;
      return o;
   }


   /**
    * Sets the content type to the given OID and clears the actual content. The OID is copied
    * by reference. Modifying it afterwards causes side effects.
    *
    * @param oid The OID that identifies the (empty) content type.
    */
   public void setContent(ASN1ObjectIdentifier oid)
   {
      clear();
      contentType = oid;
      content = null;
      add(contentType);
   }


   /**
    * This method sets the content of this structure. This method calls {@link
    * #setContent(ASN1ObjectIdentifier,ASN1Type)} with the OID returned by {@link
    * ASN1RegisteredType#getOID}.
    */
   public void setContent(ASN1RegisteredType type)
   {
      setContent(type.getOID(), type);
   }


   /**
    * This method sets the OID and content of this structure. The OID is cloned and the
    * type is stored by reference. Subsequent modification of the type has side effects.
    *
    * @param oid The OID that identifies the content type.
    * @param type The content.
    */
   public void setContent(ASN1ObjectIdentifier oid, ASN1Type type)
   {
      clear();
      contentType = (ASN1ObjectIdentifier) oid.copy();
      content = new ASN1TaggedType(0, type, true);
      add(contentType);
      add(content);
   }


   /**
    * Decodes this instance. This method extracts the actual content type from the {@link
    * ASN1OpenType}.
    *
    * @param decoder The {@link Decoder} to use.
    */
   public void decode(Decoder decoder)
      throws IOException
   {
      super.decode(decoder);
      if (!content.isOptional()) {
         ASN1Type t = content.getInnerType();

         if (t instanceof ASN1OpenType) {
            ASN1OpenType o = (ASN1OpenType) t;
            content.setInnerType(o.getInnerType());
         }
      }
   }


   public String toString()
   {
      return super.toString();
   }

}

