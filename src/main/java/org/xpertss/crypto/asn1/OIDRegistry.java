package org.xpertss.crypto.asn1;


import java.util.*;

/**
 * This class maps ASN.1 object identifiers onto ASN.1 types suitable 
 * for decoding the structure defined by the given OID. It is modelled 
 * along the lines of the ClassLoader and provides a hierarchy and 
 * top-level OID registries.
 */
public class OIDRegistry extends Object {

   /**
    * The list of global OID registries.
    */
   private static Set registries_ = Collections.synchronizedSet(new HashSet());

   /**
    * The global instance of OID registries.
    */
   private static OIDRegistry global_ = new OIDRegistry();


   /**
    * The parent OID registry.
    */
   private OIDRegistry parent_ = null;


   /**
    * Creates an OID registry.
    */
   private OIDRegistry()
   {
   }


   /**
    * This method returns the global OIDRegistry instance that may be 
    * used for querying
    *
    * @return The global OID registry.
    */
   public final static OIDRegistry getGlobalOIDRegistry()
   {
      return global_;
   }


   /**
    * Adds a registry to the set of globally known ones unless it is 
    * already in the global set. This method checks the permission if
    * a security manager is installed.
    * <p>
    * {@link ASN1Permission ASN1Permission}, &quot; OIDRegistry.add&quot;<p>
    *
    * The reference to the parent registry of the given registry is
    * cleared before it is added.
    *
    * @param r - The registry to add.
    * @exception SecurityException iff the caller has no right to add registries to
    *            the global ones.
    */
   public final static void addOIDRegistry(OIDRegistry r)
   {
      if (r == null) return;
      if(System.getSecurityManager() != null) {
         System.getSecurityManager().checkPermission(new ASN1Permission("OIDRegistry.add"));
      }
      r.parent_ = null;
      registries_.add(r);
   }


   /**
    * Removes the given OID registry from the set of globally known 
    * ones. This method checks the permission if a security manager
    * is installed.
    * <p>
    * {@link ASN1Permission ASN1Permission}, &quot; OIDRegistry.remove&quot;
    *
    * @param r The registry to remove.
    * @exception SecurityException iff the caller has no right to remove OID registries.
    */
   public final static void removeOIDRegistry(OIDRegistry r)
   {
      if (r == null) return;
      if(System.getSecurityManager() != null) {
         System.getSecurityManager().checkPermission(new ASN1Permission("OIDRegistry.remove"));
      }
      registries_.remove(r);
   }








   /**
    * Creates an OID registry with the given parent. If an OID is not 
    * found by this registry then the search is delegated to the parent 
    * registry.
    *
    * @param parent The parent OID registry.
    */
   public OIDRegistry(OIDRegistry parent)
   {
      parent_ = parent;
   }




   /**
    * Retrieves an ASN.1 type based on the given OID. If no type is 
    * found then <code>null</code> is returned. This method first 
    * calls {@link #getLocalASN1Type getLocalASN1Type}. If no ASN.1 
    * type is found for the given OID then <code>getASN1Type</code> 
    * is called for the parent OIDRegistry.
    *
    * @param oid The registered OID of the desired type.
    * @return The type or <code>null</code> if no type with the given OID is known.
    */
   public final ASN1Type getASN1Type(ASN1ObjectIdentifier oid)
   {
      ASN1Type o = getLocalASN1Type(oid);
      if (o == null && parent_ != null)
         return parent_.getASN1Type(oid);
      return o;
   }



   /**
    * Retrieves an ASN.1 type for the given OID or <code>null</code> 
    * if no such type was found. OIDRegistry implmentations should 
    * override and implement this method.
    *
    */
   protected ASN1Type getLocalASN1Type(ASN1ObjectIdentifier oid)
   {
      for (Iterator i = registries_.iterator(); i.hasNext();) {
         OIDRegistry r = (OIDRegistry) i.next();
         ASN1Type o = r.getASN1Type(oid);
         if (o != null) return o;
      }
      return null;
   }





   /**
    * An OIDRegistry equals another iff both are of the same class.
    *
    * @return <code>true</code> if both registries are of the same class.
    */
   public boolean equals(Object o)
   {
      if (getClass() == o.getClass()) return true;
      return false;
   }


   /**
    * The hash code of an instance is the hash code of its class. 
    * This is required to be consistent with the {@link #equals 
    * equals()} method.
    */
   public int hashCode()
   {
      return getClass().hashCode();
   }

}
