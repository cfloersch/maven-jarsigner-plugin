package org.xpertss.crypto.asn1;

/**
 * Thrown by {@link Resolver resolvers} if a problem
 * is detected.
 */
public class ResolverException extends ASN1Exception {

   public ResolverException()
   {
   }

   public ResolverException(String message)
   {
      super(message);
   }

}
