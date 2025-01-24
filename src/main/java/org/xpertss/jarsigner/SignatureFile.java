package org.xpertss.jarsigner;

import java.security.PrivateKey;
import java.util.Locale;



/*

Example
  Notice line length is limited to 70 chars, wrapped line is indented
  by a single space

  Also note that the SHA-256-Digest in this file does not match the
  SHA-256-Digest in the actual Manifest file.



Signature-Version: 1.0
SHA-256-Digest-Manifest-Main-Attributes: KUQaWc0H7aS83+OjigPzkJT/fPgyZ
 p7Zb4k9cvLoVOc=
SHA-256-Digest-Manifest: Kds7VEe/DjHhdchwF3rRwRQUrwwHyMm92Nmi0dCZSZc=
Created-By: 1.8.0_432 (Temurin)

Name: com/manheim/simulcast/cache/Cache.class
SHA-256-Digest: WHmcmNAoJPQ295M7raATOqQLnOHhfN1DLKZ0xwvyndA=

Name: com/manheim/simulcast/messaging/Message$MessageIterator.class
SHA-256-Digest: OXsuYkqFB6ifklZ7ScBh0N1Wb2iEWmJA6IMSdstVZ64=

Name: com/manheim/simulcast/swing/Adapted.class
SHA-256-Digest: U1pybKdULPdFf/bUJkQ9AmGvWFtRNI8ZMrJtvsmoJe0=

Name: com/manheim/simulcast/core/impl/NoBuyPermission.class
SHA-256-Digest: F8s1XJqfw6qO1B6HtYwuNe6C4U5qk7rc9KYEcxMxZ74=

Name: com/manheim/simulcast/messaging/messages/OKSALEMessage.class
SHA-256-Digest: cnhucqOfUptZ3UbFJivnEH8hnQujGzTrT3KObJZ6znI=

Name: META-INF/Facility.properties
SHA-256-Digest: AYab7WJP27eHB1Q5ZyYFv2oQ9dX/rB5xwP2Xi5RxqUk=

Name: com/manheim/simulcast/utilities/collections/FunctionUtils.class
SHA-256-Digest: 1wmFEj2OmPKWdVvLEBP7KzWoIfOv235mbnPvw5xCAVo=

Name: com/manheim/simulcast/biddisplay/DefaultFlashingStrategy$LaneMod
 elEventHandler.class
SHA-256-Digest: 3qbfZ3CnHmSK1smtxKx2KI+3qOyfTvm7loN2WdG3qYU=

Name: com/manheim/simulcast/messaging/json/JsonMessageDeserializer$1.c
 lass
SHA-256-Digest: Y1ZsR79kkhSexPsCdHJcTKVUo9/Tek9suk9H3+V5adk=
 */

public class SignatureFile {

   private final String name;

   private SignatureFile(String name)
   {
      this.name = name;
   }

   public String getName()
   {
      return name;
   }



   public byte[] generateBlock()
   {
      // TODO Needs Signature and TSASigner.. Generates PKCS#7 signature block
      return null;
   }


   // get .DSA (or .DSA, .EC) file name
   public String getBlockName(PrivateKey privateKey)
   {
      String keyAlgorithm = privateKey.getAlgorithm();
      return "META-INF/" + name + "." + keyAlgorithm;
   }



   // get .SF file name
   public String getMetaName()
   {
      return "META-INF/" + name + ".SF";
   }



   public static SignatureFile create(String name)
   {
      return new SignatureFile(encodeName(name));
   }


   
   private static String encodeName(String sigfile)
   {
      if (sigfile.length() > 8) {
         sigfile = sigfile.substring(0, 8).toUpperCase(Locale.ENGLISH);
      } else {
         sigfile = sigfile.toUpperCase(Locale.ENGLISH);
      }

      StringBuilder tmpSigFile = new StringBuilder(sigfile.length());
      for (int j = 0; j < sigfile.length(); j++) {
         char c = sigfile.charAt(j);
         if (!((c>= 'A' && c<= 'Z') || (c>= '0' && c<= '9') || (c == '-') || (c == '_'))) {
            // convert illegal characters from the alias to be _'s
            c = '_';
         }
         tmpSigFile.append(c);
      }
      return tmpSigFile.toString();
   }

}
