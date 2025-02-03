package org.xpertss.jarsigner.jar;


import org.xpertss.crypto.asn1.DEREncoder;
import org.xpertss.crypto.pkcs.pkcs7.ContentInfo;
import org.xpertss.crypto.pkcs.pkcs7.SignedData;
import org.xpertss.crypto.pkcs.pkcs7.SignerInfo;
import org.xpertss.jarsigner.TsaSigner;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.util.Map;
import java.util.stream.Stream;



/*

JAR File Specification + Signature Specs
https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html

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
   private final Main main;
   private final Map<String,Section> sections;

   SignatureFile(String name, Main main, Map<String,Section> sections)
   {
      this.name = name;
      this.main = main;
      this.sections = sections;
   }



   public Main getMain()
   {
      return main;
   }

   
   public Section getSection(String name)
   {
      return sections.get(name);
   }

   public Stream<Section> sections()
   {
      return sections.values().stream();
   }







   public SignatureBlock generateBlock(Signature signature, CertPath certPath, TsaSigner tsaSigner)
      throws SignatureException, NoSuchAlgorithmException
   {
      signature.update(main.getEncoded());
      for(Section section : sections.values()) {
         signature.update(section.getEncoded());
      }
      byte[] sigbytes = signature.sign();


      SignedData signedData = new SignedData();
      signedData.setContentType(ContentInfo.DATA_OID);
      SignerInfo signer = signedData.newSigner(certPath, signature.getAlgorithm());
      signer.setEncryptedDigest(sigbytes);

      // TODO Create Unauthenticated Attribute for tsaSigner Timestamp
      // Attributes unauth = (tsaSigner != null) ? tsaSigner.stamp(sigbytes) : null;
      // signer.addUnauthenticatedAttribute(unauth);


      ContentInfo content = new ContentInfo(signedData);

      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      try(DEREncoder encoder = new DEREncoder(baos)) {
         content.encode(encoder);
      } catch(IOException e) {
         throw new SignatureException(e);
      }

      return new SignatureBlock(name, algorithmFor(signature.getAlgorithm()), baos.toByteArray());
   }



   // get .DSA (or .DSA, .EC) file name






   
   // get .SF file name
   public String getMetaName()
   {
      return "META-INF/" + name + ".SF";
   }


   public void writeTo(OutputStream out)
      throws IOException
   {
      out.write(main.getEncoded());
      for(Section section : sections.values()) {
         out.write(section.getEncoded());
      }
      out.flush();
   }







   private static String algorithmFor(String sigalg)
   {
      if(sigalg.startsWith("RSA")) {
         return "RSA";
      } else if(sigalg.endsWith("ECDSA")) {
         return "EC";
      } else if(sigalg.endsWith("DSA")) {
         return "DSA";
      }
      throw new RuntimeException("Unknown signature algorithm - " + sigalg);
   }



}
