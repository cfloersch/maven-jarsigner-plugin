package org.xpertss.crypto.pkcs.pkcs7;

import org.xpertss.crypto.asn1.*;

/**
 * This class represents the PKCS#7 Data type that is defined as:
 * <pre>
 *   Data ::= OCTET STRING
 * </pre>
 * It serves as a wrapper around arbitrary contents octets.
 */
public class Data extends ASN1OctetString implements ASN1RegisteredType {
   /**
    * The OID of this structure. PKCS#7 Data
    */
   private static final int[] oid_ = {1, 2, 840, 113549, 1, 7, 1};

   /**
    * Returns the OID of this structure.
    *
    * @return The OID.
    */
   public ASN1ObjectIdentifier getOID()
   {
      return new ASN1ObjectIdentifier(oid_);
   }


   /**
    * Creates an empty instance ready for parsing.
    */
   public Data()
   {
      super();
   }

   /**
    * Creates an instance initialised with the given contents octets.
    *
    * @param content The content of this structure.
    */
   public Data(byte[] content)
   {
      super(content);
   }




   public String toString()
   {
      return "PKCS#7 Data {" + super.toString() + "}";
   }


}
