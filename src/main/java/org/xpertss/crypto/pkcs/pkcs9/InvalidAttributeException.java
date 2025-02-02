package org.xpertss.crypto.pkcs.pkcs9;


/**
 * Thrown when a given <code>Attribute</code> does not match
 * a required one, e.g. if the authenticated PKCS#9 ContentType
 * attribute of a <code>SignerInfo</code> does not match the
 * content type of a corresponding <code>SignedData</code>.
 */
public class InvalidAttributeException extends Exception {

   /**
    * Creates an instance.
    */
   public InvalidAttributeException()
   {
      super();
   }


   /**
    * Creates an instance with the given message.
    *
    * @param message The message.
    */
   public InvalidAttributeException(String message)
   {
      super(message);
   }
}
