package org.xpertss.crypto.pkcs;

import org.xpertss.crypto.asn1.*;

import java.util.*;
import java.io.*;

/**
 * This class maps ASN.1 object identifiers onto ASN.1 types suitable for decoding
 * the structure defined by the given OID.
 */
public class PKCSRegistry extends OIDRegistry {
   /**
    * The base name of files that map OIDs to the names of classes
    * that represent and implement the ASN.1 structure with the
    * respective OIDs.
    */
   public static final String RN = "META-INF/pkcs/oid";

   /**
    * The mapping from OID to ASN.1 types implementing encoding and decoding of the
    * ASN.1 structure registered under the given OID.<p>
    */
   private static final Map<ASN1ObjectIdentifier,Class<?>> map_ = Collections.synchronizedMap(new HashMap<>());

   /**
    * The default PKCS#7 OID registry. This instance
    * calls the global registry if a requested OID
    * could not be found locally.
    */
   private static final PKCSRegistry default_ = new PKCSRegistry(OIDRegistry.getGlobalOIDRegistry());


   /* Initializes the OID mappings of this registry.
    */
   static
   {

      int n = 0;
      InputStream in = ClassLoader.getSystemResourceAsStream(RN + "0.map");

      while (in != null) {
         try {
            Properties props = new Properties();
            props.load(in);

            for (Iterator i = props.entrySet().iterator(); i.hasNext();) {
               Map.Entry entry = (Map.Entry) i.next();
               try {
                  ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier((String) entry.getKey());
                  Class<?> cls = Class.forName((String) entry.getValue());
                  if(ASN1Type.class.isAssignableFrom(cls))
                     map_.put(oid, cls);
                  else
                     throw new Exception();
               } catch(Exception ex) {
                  System.err.println("Bad OID entry " + entry);
               }
            }
         } catch (Exception e) {
            System.err.println("Bad OID map file: " + RN + n + ".map");
         } finally {
            try {
               in.close();
            } catch (IOException e) { }
         }
         n++;
         in = ClassLoader.getSystemResourceAsStream(RN + n + ".map");
      }
   }


   /**
    * Creates an instance of this class with no parent.
    */
   public PKCSRegistry()
   {
      this(null);
   }


   /**
    * Creates an instance with the given parent.
    *
    * @param parent the parent OID registry.
    */
   public PKCSRegistry(OIDRegistry parent)
   {
      super(parent);
   }


   /**
    * Retrieves an ASN.1 type for the given OID or <code>null</code> if no such type
    * was found.
    */
   protected ASN1Type getLocalASN1Type(ASN1ObjectIdentifier oid)
   {
      Class<?> c = map_.get(oid);
      ASN1Type result = null;
      try {
         result = (ASN1Type) c.newInstance();
      } catch(Exception ex) {
         result = super.getLocalASN1Type(oid);
      }
      return (result != null) ? result : new ASN1Opaque();
   }


   /**
    * This method returns the default PKCS#7 OID registry. The default registry delegates
    * to the global OID registry if a requested OID could not be found locally.
    *
    * @return The default PKCS#7 OID registry.
    */
   public static OIDRegistry getDefaultRegistry()
   {
      return default_;
   }

}
