package org.xpertss.crypto.pkcs.pkcs7;


import java.security.SignatureException;

/**
 * Thrown when a <code>SignerInfo</code> is not found. This
 * can happen e.g. when a <code>Verifier</code> is initialized
 * with a certificate and <code>SignedData</code> but the
 * <code>SignedData</code> instance does not contain a <code>
 * SignerInfo</code> that matches the subject of the given
 * certificate.
 */
public class NoSuchSignerException extends SignatureException {

   /**
    * Creates an instance.
    */
   public NoSuchSignerException()
   {
      super();
   }


   /**
    * Creates an instance with the given message.
    *
    * @param message The message.
    */
   public NoSuchSignerException(String message)
   {
      super(message);
   }
}
