package org.xpertss.jarsigner.jar;

import java.io.IOException;
import java.io.OutputStream;

public class SignatureBlock {

   private final String name;
   private final String algorithm;
   private final byte[] signature;

   SignatureBlock(String name, String algorithm, byte[] signature)
   {
      this.name = name;
      this.algorithm = algorithm;
      this.signature = signature.clone();
   }



   // TODO Anything around verify??

   public byte[] getSignature()
   {
      return signature.clone();
   }



   public String getMetaName()
   {
      return "META-INF/" + name + "." + algorithm;
   }


   public void write(OutputStream out)
      throws IOException
   {
   }
}
