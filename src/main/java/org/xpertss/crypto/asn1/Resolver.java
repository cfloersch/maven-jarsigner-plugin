package org.xpertss.crypto.asn1;


/**
 * This interface is used by the {@link ASN1OpenType ASN1OpenType} 
 * in order to resolve the ASN.1 type to decode at runtime. Concrete 
 * implementations of this interface can be used to model references 
 * to type classes as well or to compensate for the superseded ASN.1 
 * ANY DEFINED BY type.
 * <p>
 * Implementations shall determine and return the correct ASN.1 type 
 * to be decoded in the defined method.
 */
public interface Resolver {
   public ASN1Type resolve(ASN1Type caller) throws ResolverException;
}




