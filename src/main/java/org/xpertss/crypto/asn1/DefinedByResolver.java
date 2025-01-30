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
public class DefinedByResolver extends Object implements Resolver {

   private OIDRegistry registry_;
   private ASN1ObjectIdentifier oid_;


   /**
    * Creates an instance that attempts to resolve the given
    * OID against the given registry upon calling {@link
    * #resolve resolve}. The OID instance used or resolving
    * is the one passed to this constructor. Hence, an OID can
    * be added to a compound ASN.1 type and an {@link ASN1OpenType
    * ASN1OpenType} can be initialised with this. If the
    * OID is decoded before the open type then the open type is
    * resolved against the given registry and the decoded OID.
    * In other words the ASN.1 ANY DEFINED BY type can be modelled
    * with an ASN1OpenType and an instance of this resolver class.
    *
    * @param registry The registry to resolve the given OID against.
    * @param oid The oid instance to use when resolving.
    */
   public DefinedByResolver(OIDRegistry registry, ASN1ObjectIdentifier oid)
   {
      if (registry == null || oid == null)
         throw new NullPointerException("Registry or OID is null!");

      registry_ = registry;
      oid_ = oid;
   }


   /**
    * Creates an instance that resolves the given OID against the
    * {@link OIDRegistry#getGlobalOIDRegistry global OID registry}.
    *
    * @param oid The OID to resolve.
    */
   public DefinedByResolver(ASN1ObjectIdentifier oid)
   {
      if (oid == null)
         throw new NullPointerException("OID is null!");

      registry_ = OIDRegistry.getGlobalOIDRegistry();
      oid_ = oid;
   }


   /**
    * Looks up the private OID in the private registry and returns the 
    * resolved ASN.1 type. If the OID cannot be resolved against the 
    * registry then an exception is thrown.
    *
    * @param caller The calling ASN.1 type.
    * @exception ResolverException if the private OID cannot
    *   be mapped onto an ASN.1 type by the private registry.
    */
   public ASN1Type resolve(ASN1Type caller)
      throws ResolverException
   {
      ASN1Type t = registry_.getASN1Type(oid_);
      if (t == null)
         throw new ResolverException("Cannot resolve " + oid_);
      return t;
   }
}




