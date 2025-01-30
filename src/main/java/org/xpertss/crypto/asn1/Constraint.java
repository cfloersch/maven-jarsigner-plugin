package org.xpertss.crypto.asn1;

/**
 * This interface specifies a constraint of some ASN.1 type. 
 * Constraints are called to check the validity of a type 
 * right after initialisation and after decoding. For instance 
 * an OCTET STRING may be defined to be at most 8 octets long. 
 * This may be implemented by adding a constraint to an {@link 
 * ASN1OctetString ASN1OctetString} instance that verifies the 
 * length of the octets string.
 */
public interface Constraint {

   public void constrain(ASN1Type o) throws ConstraintException;

}
