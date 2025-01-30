package org.xpertss.crypto.asn1;


/**
 * This class represents an ASN.1 type that is officially 
 * registered. In other words, this type is associated 
 * with a unique OID.
 */
public interface ASN1RegisteredType extends ASN1Type {
   /**
    * This method returns the official OID that
    * identifies this ASN.1 type.
    *
    * @return The official ASN.1 OID of this type.
    */
   public ASN1ObjectIdentifier getOID();

}
