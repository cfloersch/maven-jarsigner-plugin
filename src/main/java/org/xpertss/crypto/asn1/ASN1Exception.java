package org.xpertss.crypto.asn1;

import java.io.IOException;

/**
 * General Exception thrown by ASN Coders.
 */
public class ASN1Exception extends IOException {

   public ASN1Exception()
   {
   }

   public ASN1Exception(String message)
   {
      super(message);
   }

   public ASN1Exception(Throwable t)
   {
      super(t);
   }

   public ASN1Exception(String message, Throwable t)
   {
      super(message, t);
   }

}
