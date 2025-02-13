package org.xpertss.jarsigner;



import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 1/17/2025
 */
public class IdentityBuilderTest {

   @Test
   public void testKeyStoreNonePath()
      throws Exception
   {
      IdentityBuilder builder = new IdentityBuilder();
      builder.keyStore(Paths.get("NONE"));
   }

   @Test
   public void testKeyStorePath()
      throws Exception
   {
      IdentityBuilder builder = new IdentityBuilder();
      builder.keyStore(Paths.get("src", "test", "keystore"));
   }

   @Test
   public void testKeyStoreClearPath()
      throws Exception
   {
      IdentityBuilder builder = new IdentityBuilder();
      builder.keyStore(null);
   }

   @Test
   public void testKeyStoreDoesNotExistPath()
      throws Exception
   {
      IdentityBuilder builder = new IdentityBuilder();
      assertThrows(NoSuchFileException.class, ()->{
         builder.keyStore(Paths.get("does", "not", "exist"));
      });
   }

   @Test
   public void testKeyStoreTypeWithExistingProvider()
      throws Exception
   {
      IdentityBuilder builder = new IdentityBuilder();
      builder.storeType(null, "SUN");
   }

   @Test
   public void testKeyStoreTypeWithNonExistingProvider()
      throws Exception
   {
      IdentityBuilder builder = new IdentityBuilder();
      assertThrows(NoSuchProviderException.class, ()->{
         builder.storeType(null, "MISSING");
      });
   }






   @Test
   public void testFullKeyLoadNotStrict()
      throws Exception
   {
      IdentityBuilder builder = new IdentityBuilder();
      Identity identity = builder
                     .keyStore(Paths.get("src", "test", "keystore"))
                     .storeType("JKS")
                     .storePass(password("changeit"))
                     .keyPass(password("key-passwd"))
                     .alias("foo_alias")
                     .build();
      assertNotNull(identity);
      assertEquals("foo_alias", identity.getName());
      assertEquals("DSA", identity.getPrivateKey().getAlgorithm());
      assertEquals(1, identity.getCertificateChain().length);


      assertThat(identity.getCertificate(), instanceOf(X509Certificate.class));
      X509Certificate x509 = (X509Certificate)identity.getCertificate();
      assertEquals("CN=Olivier Lamy, OU=ASF, O=Apache, L=Marolles en Hurepoix, ST=Unknown, C=FR",
                     x509.getSubjectDN().getName());
      assertEquals(x509.getSubjectDN(), x509.getIssuerDN());
   }


   @Test
   public void testBuildMissingStorePassword()
      throws Exception
   {
      IdentityBuilder builder = new IdentityBuilder();
      assertThrows(UnrecoverableKeyException.class, ()-> {
         builder.keyStore(Paths.get("src", "test", "keystore")).storeType("JKS").storePass(password("changeit")).alias("foo_alias").build();
      });
   }


   @Test
   public void testBuildMissingKeyPassword()
      throws Exception
   {
      IdentityBuilder builder = new IdentityBuilder();
      assertThrows(UnrecoverableEntryException.class, ()-> {
         builder.keyStore(Paths.get("src", "test", "keystore")).storeType("JKS").storePass(password("changeit")).alias("foo_alias").build();
      });
   }

   @Test
   public void testBuildMissingAlias()
      throws Exception
   {
      IdentityBuilder builder = new IdentityBuilder();
      assertThrows(NullPointerException.class, ()-> {
         builder.keyStore(Paths.get("src", "test", "keystore")).storeType("JKS").storePass(password("changeit")).keyPass(password("key-passwd")).build();
      });
   }

   @Test
   public void testBuildMissingKeyStore()
      throws Exception
   {
      IdentityBuilder builder = new IdentityBuilder();
      assertThrows(NoSuchFileException.class, ()-> {
         builder.storeType("JKS").storePass(password("changeit")).keyPass(password("key-passwd")).alias("foo_alias").build();
      });
   }




   @Test
   public void testStrictBuild_ExpiredSelfSigningKeyWithNoKeyUsage()
      throws Exception
   {
      IdentityBuilder builder = new IdentityBuilder();
      CertPathValidatorException thrown = assertThrows(CertPathValidatorException.class, ()-> {
         builder.keyStore(Paths.get("src", "test", "keystore"))
                  .storeType("JKS").storePass(password("changeit"))
                  .keyPass(password("key-passwd"))
                  .alias("foo_alias").strict(true).build();
      });
      assertNotNull(thrown);
   }


   @Test
   public void testStrictBuild_NotSigningKey()
      throws Exception
   {
      TrustStore trust = TrustStore.Builder.create()
                           .trustStore(Paths.get("src", "test", "truststore"))
                           .build();

      IdentityBuilder builder = new IdentityBuilder();
      CertPathValidatorException thrown = assertThrows(CertPathValidatorException.class, ()-> {
         builder.trustStore(trust).strict(true)
                  .keyStore(Paths.get("src", "test", "keystore.p12"))
                  .storeType("PKCS12").storePass(password("changeme")).alias("tls").build();
      });
      assertNotNull(thrown);
   }

   @Test
   public void testStrictBuild_ExpiredCASignedCert()
      throws Exception
   {
      // TODO On another machine will need truststore specified
      TrustStore trust = TrustStore.Builder.create()
              .trustStore(Paths.get("src", "test", "truststore"))
              .build();


      IdentityBuilder builder = new IdentityBuilder();
      CertPathValidatorException thrown = assertThrows(CertPathValidatorException.class, ()-> {
         // will throw error on thursday
         builder.trustStore(trust).strict(true)
                  .keyStore(Paths.get("src", "test", "keystore.p12")).storeType("PKCS12")
                  .storePass(password("changeme")).alias("expired").build();
      });
      assertNotNull(thrown);
   }


   @Test
   public void testStrictBuild_ValidCodeSingingNoTrustStore()
      throws Exception
   {
      TrustStore trust = TrustStore.Builder.create()
              .trustStore(Paths.get("src", "test", "keystore"))
              .build();

      IdentityBuilder builder = new IdentityBuilder();
      CertPathValidatorException thrown = assertThrows(CertPathValidatorException.class, ()-> {
         builder.trustStore(trust).strict(true)
                     .keyStore(Paths.get("src", "test", "keystore.p12"))
                     .storeType("PKCS12")
                     .storePass(password("changeme"))
                     .alias("code").build();
      });
      assertNotNull(thrown);
   }

   
   @Test
   public void testStrictBuild_ValidCodeSinging()
      throws Exception
   {
      TrustStore trust = TrustStore.Builder.create()
              .trustStore(Paths.get("src", "test", "truststore"))
              .build();

      // TODO On another machine will need truststore specified
      IdentityBuilder builder = new IdentityBuilder();
      Identity identity = builder.trustStore(trust).strict(true)
                              .keyStore(Paths.get("src", "test", "keystore.p12"))
                              .storeType("PKCS12").storePass(password("changeme"))
                              .alias("code").build();

      assertNotNull(identity);
      assertEquals("code", identity.getName());
      assertEquals("RSA", identity.getPrivateKey().getAlgorithm());
      assertEquals(2, identity.getCertificateChain().length);


      assertThat(identity.getCertificate(), instanceOf(X509Certificate.class));
      X509Certificate x509 = (X509Certificate)identity.getCertificate();
      assertEquals("CN=Simulcast, O=Xpertss, C=US",
                     x509.getSubjectDN().getName());
      assertNotEquals(x509.getSubjectDN(), x509.getIssuerDN());

   }

   // TODO Do I really want to allow self signed?
   //  Maybe check that using something other than PKIX Cert Path Validator?
   @Test@Disabled
   public void testStrictBuild_SelfSignedCodeSigner()
      throws Exception
   {
      // No need for trust store on this one
      IdentityBuilder builder = new IdentityBuilder();
      Identity identity = builder
                              .strict(true)
                              .keyStore(Paths.get("src", "test", "keystore.p12"))
                              .storeType("PKCS12").storePass(password("changeme"))
                              .alias("self").build();


      assertNotNull(identity);
      assertEquals("self", identity.getName());
      assertEquals("RSA", identity.getPrivateKey().getAlgorithm());
      assertEquals(1, identity.getCertificateChain().length);


      assertThat(identity.getCertificate(), instanceOf(X509Certificate.class));
      X509Certificate x509 = (X509Certificate)identity.getCertificate();
      assertEquals("CN=Expired, O=Xpertss, C=US",
                     x509.getSubjectDN().getName());
      assertEquals(x509.getSubjectDN(), x509.getIssuerDN());

   }




   
   private KeyStore.PasswordProtection password(String passwd)
   {
      return new KeyStore.PasswordProtection(passwd.toCharArray());
   }


   
}