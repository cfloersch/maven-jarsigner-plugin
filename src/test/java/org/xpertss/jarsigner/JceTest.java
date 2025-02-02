/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 2/1/2025
 */
package org.xpertss.jarsigner;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.security.Provider;
import java.security.Security;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Disabled
public class JceTest {

   @Test
   public void testProviders()
   {
      Pattern pattern = Pattern.compile("ALG\\.ALIAS\\.(\\w+)\\.([\\w\\-/]+)");
      for (Provider provider : Security.getProviders()) {
         for (Object key : provider.keySet()) {
            String alias = ((String) key).toUpperCase(Locale.ENGLISH);
            String stdAlgName = provider.getProperty((String)key);
            Matcher matcher = pattern.matcher(alias);
            if (matcher.matches()) {
               System.out.printf("%s: %s%n",  matcher.group(2), stdAlgName);
            }
         }
      }
   }


   @Test
   public void testProviderOIDs()
   {
      // Looks like Sun is associating 1.2.840.113549.1.1 (pkcs1) with RSA encryption
      // when jar signer is associating 1.2.840.113549.1.1.1


      Pattern pattern = Pattern.compile("ALG\\.ALIAS\\.\\w+\\.OID\\.(\\d+(?:\\.\\d+)+)");
      for (Provider provider : Security.getProviders()) {
         for (Object key : provider.keySet()) {
            String alias = ((String) key).toUpperCase(Locale.ENGLISH);
            String stdAlgName = provider.getProperty((String)key);
            Matcher matcher = pattern.matcher(alias);
            if (matcher.matches()) {
               System.out.printf("%s: %s%n", matcher.group(1), stdAlgName);
            }
         }
      }
   }

}
