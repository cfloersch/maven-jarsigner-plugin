package org.xpertss.crypto.pkcs.pkcs9;


/**
 * Thrown when a <code>Attribute</code> is not found.
 */
public class NoSuchAttributeException extends Exception {

   /**
    * Creates an instance.
    */
   public NoSuchAttributeException()
   {
      super();
   }


   /**
    * Creates an instance with the given message.
    *
    * @param message The message.
    */
   public NoSuchAttributeException(String message)
   {
      super(message);
   }
}
