/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 2/8/2025
 */
package org.xpertss.jarsigner.tsa;

import javax.security.auth.Destroyable;
import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.SocketAddress;

public final class AuthenticatedProxy extends Proxy {

   private PasswordAuthenticator authenticator;

   /**
    * Creates an entry representing a PROXY connection. Certain combinations are illegal. For
    * instance, for types Http, and Socks, a SocketAddress <b>must</b> be provided.
    * <p>
    * Use the {@code Proxy.NO_PROXY} constant for representing a direct connection.
    *
    * @param type the {@code Type} of the proxy
    * @param sa   the {@code SocketAddress} for that proxy
    * @param username The username to use through the proxy
    * @param password The password to use through the proxy
    * @throws IllegalArgumentException when the type and the address are incompatible
    */
   public AuthenticatedProxy(Type type, SocketAddress sa, String username, String password)
   {
      super(type, sa);
      this.authenticator = new PasswordAuthenticator(sa, username, password);
   }


   /**
    * Returns the password authenticator that is used with this proxy.
    */
   public Authenticator getAuthenticator()
   {
      return authenticator;
   }




   private static class PasswordAuthenticator extends Authenticator implements Destroyable {

      private final String username;
      private final char[] password;

      private SocketAddress sa;

      public PasswordAuthenticator(SocketAddress sa, String username, String password)
      {
         this.sa = sa;
         this.username = username;
         this.password = password.toCharArray();
      }



      protected PasswordAuthentication getPasswordAuthentication()
      {
         // TODO Make sure host is correct before returning
         //  if direct then must match target uri otherwise must match proxy host

         //getRequestorType();
         //getRequestingURL();

         //getRequestingScheme();
         //getRequestingSite();

         //getRequestingHost();
         //getRequestingPort();

         InetSocketAddress target = new InetSocketAddress(getRequestingHost(), getRequestingPort());

         
         if(!sa.equals(target)) return null;
         return new PasswordAuthentication(username, password.clone());
      }

   }

}
