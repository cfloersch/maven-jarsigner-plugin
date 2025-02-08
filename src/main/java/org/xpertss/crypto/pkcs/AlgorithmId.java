/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 2/1/2025
 */
package org.xpertss.crypto.pkcs;

import org.xpertss.crypto.asn1.ASN1ObjectIdentifier;

import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AlgorithmId {

   private static volatile Map<String,ASN1ObjectIdentifier> oidTable;
   private static volatile Map<ASN1ObjectIdentifier,String> nameTable;






   public static ASN1ObjectIdentifier lookup(String algorithmName)
      throws NoSuchAlgorithmException
   {
      if(algorithmName == null) throw new NoSuchAlgorithmException("null algorithm cannot be found");
      ASN1ObjectIdentifier oid = oidTable().get(algorithmName.toUpperCase(Locale.ENGLISH));
      if(oid == null) throw new NoSuchAlgorithmException("unknown algorithm " + algorithmName);
      return oid;
   }

   public static String lookup(ASN1ObjectIdentifier oid)
      throws NoSuchAlgorithmException
   {
      String name = nameTable().get(oid);
      if(name == null) throw new NoSuchAlgorithmException("unknown algorithm for " + oid);
      return name;
   }







   /**
    * Creates a signature algorithm name from a digest algorithm
    * name and a encryption algorithm name.
    */
   public static String makeSigAlg(String digAlg, String encAlg)
   {
      digAlg = digAlg.replace("-", "");
      if (encAlg.equalsIgnoreCase("EC")) encAlg = "ECDSA";
      return digAlg + "with" + encAlg;
   }



   /**
    * Extracts the encryption algorithm name from a signature
    * algorithm name.
    */
   public static String getEncAlgFromSigAlg(String signatureAlgorithm)
   {
      signatureAlgorithm = signatureAlgorithm.toUpperCase(Locale.ENGLISH);
      int with = signatureAlgorithm.indexOf("WITH");
      String keyAlgorithm = null;
      if (with > 0) {
         int and = signatureAlgorithm.indexOf("AND", with + 4);
         if (and > 0) {
            keyAlgorithm = signatureAlgorithm.substring(with + 4, and);
         } else {
            keyAlgorithm = signatureAlgorithm.substring(with + 4);
         }
         if (keyAlgorithm.equalsIgnoreCase("ECDSA")) {
            keyAlgorithm = "EC";
         }
      }
      return keyAlgorithm;
   }

   /**
    * Extracts the digest algorithm name from a signature
    * algorithm name.
    */
   public static String getDigAlgFromSigAlg(String signatureAlgorithm)
   {
      signatureAlgorithm = signatureAlgorithm.toUpperCase(Locale.ENGLISH);
      int with = signatureAlgorithm.indexOf("WITH");
      if (with > 0) {
         return signatureAlgorithm.substring(0, with);
      }
      return null;
   }



   /**
    * Returns the default signature algorithm for a private key. The digest
    * part might evolve with time.
    *
    * @param k cannot be null
    * @return the default alg, might be null if unsupported
    */
   public static String getDefaultSigAlgForKey(PrivateKey k)
   {
      switch (k.getAlgorithm().toUpperCase(Locale.ENGLISH)) {
         case "EC":
            return ecStrength(getKeySize(k))
               + "withECDSA";
         case "DSA":
            return ifcFfcStrength(getKeySize(k))
               + "withDSA";
         case "RSA":
            return ifcFfcStrength(getKeySize(k))
               + "withRSA";
         default:
            return null;
      }
   }

   // Values from SP800-57 part 1 rev 4 tables 2 and 3
   private static String ecStrength (int bitLength)
   {
      if (bitLength >= 512) { // 256 bits of strength
         return "SHA512";
      } else if (bitLength >= 384) {  // 192 bits of strength
         return "SHA384";
      } else { // 128 bits of strength and less
         return "SHA256";
      }
   }

   // Same values for RSA and DSA
   private static String ifcFfcStrength (int bitLength)
   {
      if (bitLength > 7680) { // 256 bits
         return "SHA512";
      } else if (bitLength > 3072) {  // 192 bits
         return "SHA384";
      } else  { // 128 bits and less
         return "SHA256";
      }
   }
   






   private static Map<String,ASN1ObjectIdentifier> oidTable()
   {
      // Double checked locking; safe because oidTable is volatile
      Map<String,ASN1ObjectIdentifier> tab;
      if ((tab = oidTable) == null) {
         synchronized (AlgorithmId.class) {
            if ((tab = oidTable) == null)
               oidTable = tab = computeOidTable();
         }
      }
      return tab;
   }

   private static Map<ASN1ObjectIdentifier, String> nameTable()
   {
      // Double checked locking; safe because oidTable is volatile
      Map<ASN1ObjectIdentifier, String> tab;
      if ((tab = nameTable) == null) {
         synchronized (AlgorithmId.class) {
            if ((tab = nameTable) == null)
               nameTable = tab = computeNameTable();
         }
      }
      return tab;
   }


   /** Collects the algorithm names from the installed providers. */
   private static Map<String,ASN1ObjectIdentifier> computeOidTable()
   {
      // TODO As much as I might want to use the Provider model below it seems it is ill equipped.
      //  Move to a oid map file which will allow me to be much more precise but limited to know things
      Map<String,ASN1ObjectIdentifier> tab = new HashMap<>();
      Pattern pattern = Pattern.compile("ALG\\.ALIAS\\.\\w+\\.OID\\.(\\d+(?:\\.\\d+)+)");
      for (Provider provider : Security.getProviders()) {
         for (Object key : provider.keySet()) {
            String alias = ((String) key).toUpperCase(Locale.ENGLISH);
            String stdAlgName = provider.getProperty((String)key);
            Matcher matcher = pattern.matcher(alias);
            if (matcher.matches()) {
               // Short name is required for SHA256 to be found
               String shortAlgName = stdAlgName.replace("-", "").replace("_", "");
               ASN1ObjectIdentifier algIdent = new ASN1ObjectIdentifier(matcher.group(1));
               //System.out.println(stdAlgName);

               tab.putIfAbsent(stdAlgName.toUpperCase(Locale.ENGLISH), algIdent);
               tab.putIfAbsent(shortAlgName.toUpperCase(Locale.ENGLISH), algIdent);
            }
         }
      }
      
      // Fix a couple - This list is proof that maybe I ought to just define them myself rather than rely on Providers
      tab.put("RSA", new ASN1ObjectIdentifier("1.2.840.113549.1.1.1"));
      tab.put("RSASSA-PSS", new ASN1ObjectIdentifier("1.2.840.113549.1.1.10"));
      tab.put("RSAES-OAEP", new ASN1ObjectIdentifier("1.2.840.113549.1.1.7"));
      tab.put("EC", new ASN1ObjectIdentifier("1.2.840.10045.2.1"));

      tab.put("MD5", new ASN1ObjectIdentifier("1.2.840.113549.2.5"));
      tab.put("MD2", new ASN1ObjectIdentifier("1.2.840.113549.2.2"));
      tab.put("ECDH", new ASN1ObjectIdentifier("1.3.132.1.12"));
      tab.put("DSS", new ASN1ObjectIdentifier("1.2.840.10040.4.3"));
      tab.put("AES", new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1"));

      return tab;
   }


   /*
       May need others like
         AES            2, 16, 840, 1, 101, 3, 4, 1
         SHA1with RSA   1, 3, 14, 3, 2, 29                        (Legacy)
         EC             1, 2, 840, 10045, 2, 1
         ECDH           1, 3, 132, 1, 12

         DH_data = { 1, 2, 840, 113549, 1, 3, 1 };
         DH_PKIX_data = { 1, 2, 840, 10046, 2, 1 };
         DSA_OIW_data = { 1, 3, 14, 3, 2, 12 };
         DSA_PKIX_data = { 1, 2, 840, 10040, 4, 1 };
         RSA_data = { 2, 5, 8, 1, 1 };
         shaWithDSA_OIW_data = { 1, 3, 14, 3, 2, 13 };
         sha1WithDSA_OIW_data = { 1, 3, 14, 3, 2, 27 };
         dsaWithSHA1_PKIX_data = { 1, 2, 840, 10040, 4, 3 };

         sha512_224WithRSAEncryption_oid = (1, 2, 840, 113549, 1, 1, 15)            SHA512/224withRSA
         sha512_256WithRSAEncryption_oid = (1, 2, 840, 113549, 1, 1, 16)            SHA512/256withRSA

         specifiedWithECDSA_oid = (1, 2, 840, 10045, 4, 3)  ???

         pbeWithMD5AndRC2_oid = {1, 2, 840, 113549, 1, 5, 6};
         pbeWithSHA1AndDES_oid = {1, 2, 840, 113549, 1, 5, 10};
         pbeWithSHA1AndRC2_oid = {1, 2, 840, 113549, 1, 5, 11};
         

    */

   private static Map<ASN1ObjectIdentifier,String> computeNameTable()
   {
      Map<ASN1ObjectIdentifier,String> tab = new HashMap<>();
      Pattern pattern = Pattern.compile("ALG\\.ALIAS\\.\\w+\\.OID\\.(\\d+(?:\\.\\d+)+)");
      for (Provider provider : Security.getProviders()) {
         for (Object key : provider.keySet()) {
            String alias = ((String) key).toUpperCase(Locale.ENGLISH);
            String stdAlgName = provider.getProperty((String)key);
            Matcher matcher = pattern.matcher(alias);
            if (matcher.matches()) {
               tab.put(new ASN1ObjectIdentifier(matcher.group(1)), stdAlgName);
            }
         }
      }
      // Fix a couple
      tab.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.1"), "RSA");
      tab.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.10"), "RSASSA-PSS");
      tab.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.7"), "RSAES-OAEP");
      return tab;
   }








   /**
    * Returns the key size of the given key object in bits.
    *
    * @param key the key object, cannot be null
    * @return the key size of the given key object in bits, or -1 if the
    *       key size is not accessible
    */
   private static final int getKeySize(Key key)
   {
      int size = -1;

      // try to parse the length from key specification
      if (key instanceof SecretKey) {
         SecretKey sk = (SecretKey)key;
         String format = sk.getFormat();
         if ("RAW".equals(format) && sk.getEncoded() != null) {
            size = (sk.getEncoded().length * 8);
         }   // Otherwise, it may be a unextractable key of PKCS#11, or
         // a key we are not able to handle.
      } else if (key instanceof RSAKey) {
         RSAKey pubk = (RSAKey)key;
         size = pubk.getModulus().bitLength();
      } else if (key instanceof ECKey) {
         ECKey pubk = (ECKey)key;
         size = pubk.getParams().getOrder().bitLength();
      } else if (key instanceof DSAKey) {
         DSAKey pubk = (DSAKey)key;
         DSAParams params = pubk.getParams();    // params can be null
         size = (params != null) ? params.getP().bitLength() : -1;
      } else if (key instanceof DHKey) {
         DHKey pubk = (DHKey)key;
         size = pubk.getParams().getP().bitLength();
      }

      // Otherwise, it may be a unextractable key of PKCS#11, or
      // a key we are not able to handle.

      return size;
   }
   
}
