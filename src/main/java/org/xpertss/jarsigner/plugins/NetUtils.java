/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 2/9/2025
 */
package org.xpertss.jarsigner.plugins;

import java.net.InetAddress;

public final class NetUtils {

   private NetUtils() { }


   /**
    * This method takes a host pattern in the form.
    * <p>
    * <pre>
    *    127.0.0.*
    *       or
    *    *.domain.com
    *       or
    *    hostname
    *       or
    *    hostname.domain.com
    *       or
    *    [::1]
    * </pre><p>
    * and checks to see if it matches the supplied host. The inet address will provide name
    * service resolution to enable both IP based and host based wildcard matching.
    */
   public static boolean matches(String pattern, InetAddress host)
   {
      // NOTE with IP suffix wildcards, it might have been easier to do CIDR
      if(pattern == null || host == null) return false;
      if(pattern.endsWith(".*")) {
         // IP Address wildcard match
         String ip = host.getHostAddress();
         return ip.startsWith(pattern.substring(0, pattern.length() - 1));
      } else if(pattern.startsWith("*.")) {
         // Domain wildcard match
         String domain = host.getCanonicalHostName();
         return domain.endsWith(pattern.substring(1));
      } else {
         InetAddress[] rAddr = getInetAddresses(pattern);
         for(InetAddress aRAddr : (rAddr != null) ? rAddr : new InetAddress[0]) {
            if(aRAddr.equals(host)) return true;
         }
      }
      return false;
   }

   /**
    * Get all InetAddresses for the given name returning {@code null} if there is an
    * error resolving the name.
    */
   public static InetAddress[] getInetAddresses(String name)
   {
      try { return InetAddress.getAllByName(name); } catch(Exception ex) { return null; }
   }

   public static InetAddress getInetAddress(String name)
   {
      try { return InetAddress.getByName(name); } catch(Exception ex) { return null; }
   }


}
