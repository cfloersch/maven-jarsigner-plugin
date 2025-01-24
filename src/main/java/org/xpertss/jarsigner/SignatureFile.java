package org.xpertss.jarsigner;

import java.util.Locale;

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
