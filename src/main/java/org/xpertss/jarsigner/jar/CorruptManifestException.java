/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 1/26/2025
 */
package org.xpertss.jarsigner.jar;

import java.io.IOException;

public class CorruptManifestException extends IOException {

   public CorruptManifestException()
   {
      super();
   }

   public CorruptManifestException(String msg)
   {
      super(msg);
   }

   public CorruptManifestException(Throwable cause)
   {
      super(cause);
   }

   public CorruptManifestException(String msg, Throwable cause)
   {
      super(msg, cause);
   }
}
