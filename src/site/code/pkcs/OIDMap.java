/*
 * Created by IntelliJ IDEA.
 * User: Administrator
 * Date: May 6, 2003
 * Time: 8:48:54 PM
 * To change template for new class use
 * Code Style | Class Templates options (Tools | IDE Options).
 */
package org.xpertss.crypto.pkcs;

import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;
import java.security.Provider;
import java.security.Security;


/**
 * TODO: The initalization may overwrite entries. Is this what we want?
 */
public class OIDMap {

   private static final Map oidMap = initMap();


   public static String getOID(String algName)
   {
      String s = (String) oidMap.get(algName);
      if (s != null) return s;
      return (isOID(algName)) ? algName : null;
   }


   private static final boolean isOID(String s)
   {
      if (s == null) return false;
      for (int i = 0; i < s.length(); i++) {
         char c = s.charAt(i);
         if (c != '.' && Character.isDigit(c) == false) return false;
      }
      return true;
   }


   private static Map initMap()
   {
      HashMap oidMap = new HashMap();
      try {
         Provider[] providers = Security.getProviders();
         for (int i = 0; i < providers.length; i++) {
            Iterator it = providers[i].keySet().iterator();
            while (it.hasNext()) {
               String key = (String) it.next();
               if (key.startsWith("OID.") && key.length() > 4) {
                  String oid = (String) providers[i].get(key);
                  String algName = key.substring(4);
                  oidMap.put(algName, oid);
               }
            }
         }
      } catch (Exception ex) {
      }
      return oidMap;
   }

}
