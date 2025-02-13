/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 1/17/2025
 */
package org.xpertss.jarsigner;


import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

/**
 *  Used to parse arguments into an Identity which is loaded from an underlying KeyStore and or a
 *  certificate chain file. Given certain parameters this will ensure the Identity has appropriate
 *  certificate trust/usages to be used for code signing.
 *  <p/>
 *  An optional trust store can be used to determine if the certificate is trusted as part of that
 *  checking, overriding the default trusted ca certs database in java.
 */
public class IdentityBuilder {

   private static final Path NONE = Paths.get("NONE");


   private String alias;
   private String storeType;

   private TrustStore trustStore;
   private Path keyStore;

   private Provider provider;

   private Path certChain;

   private boolean strict;

   private KeyStore.PasswordProtection keyPass;
   private KeyStore.PasswordProtection storePass;


   /**
    * Force the validation of the given Identity's certificate to ensure it is trusted, is
    * configured for Code Signing, and has either digital signature or non-repudiation key
    * usages set.
    *
    * @param strict True to validate the signing certificate
    */
   public IdentityBuilder strict(boolean strict)
   {
      this.strict = strict;
      return this;
   }

   /**
    * The alias of the identity within the key store.
    *
    * @param alias The alias of the identity
    */
   public IdentityBuilder alias(String alias)
   {
      this.alias = alias;
      return this;
   }


   /**
    * Specify a trust store that can be used to validate the signer certificate.
    *
    * @param trustStore The TrustStore to utilize for certificate validation
    */
   public IdentityBuilder trustStore(TrustStore trustStore)
   {
      this.trustStore = trustStore;
      return this;
   }


   /**
    * Specify the path to a keystore file. Can be <i>NONE</i> for keystores that utilize
    * hardware or similar as opposed to an actual file.
    *
    * @param keyStore The keystore path.
    * @throws NoSuchFileException If the path does not exist or is unreadable
    */
   public IdentityBuilder keyStore(Path keyStore)
      throws NoSuchFileException
   {
      if(keyStore != null && !keyStore.equals(NONE) && (!Files.exists(keyStore) || !Files.isReadable(keyStore))) {
         throw new NoSuchFileException(String.format("Keystore %s not found", keyStore));
      }
      this.keyStore = keyStore;
      return this;
   }


   /**
    * Specify the store type (ex: PKCS12)
    *
    * @param storeType The store type
    */
   public IdentityBuilder storeType(String storeType)
   {
      this.storeType = storeType;
      return this;
   }

   /**
    * Specify the store type and store provider.
    *
    * @param storeType The store type (ex PKCS12)
    * @param providerName The name of the store's provider impl
    * @throws NoSuchProviderException If the named provider is not known to the VM
    */
   public IdentityBuilder storeType(String storeType, String providerName)
      throws NoSuchProviderException
   {
      if(providerName != null && (this.provider = Security.getProvider(providerName)) == null) {
         throw new NoSuchProviderException(String.format("No Provider %s found", providerName));
      }
      this.storeType = storeType;
      return this;
   }


   /**
    * Provide the individual identity's key password.
    *
    * @param keyPass The password protection property for the key
    */
   public IdentityBuilder keyPass(KeyStore.PasswordProtection keyPass)
   {
      this.keyPass = keyPass;
      return this;
   }

   /**
    * Provide the store's password.
    *
    * @param storePass The password protection property for the store
    */
   public IdentityBuilder storePass(KeyStore.PasswordProtection storePass)
   {
      this.storePass = storePass;
      return this;
   }


   /**
    * Specify the path to an X509 certificate chain file.
    *
    * @param certChain Path to certificate chain file
    * @throws NoSuchFileException if the given file path does not exist or is unreadable
    */
   public IdentityBuilder certificateChain(Path certChain)
      throws NoSuchFileException
   {
      this.certChain = validate(certChain, "CertChain");
      return this;
   }



   public Identity build()
      throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException,
               UnrecoverableEntryException, InvalidAlgorithmParameterException, CertPathValidatorException
   {
      try {
         if(alias == null) throw new NullPointerException("Identity alias cannot be null");

         KeyStore store = createKeyStoreInstance();
         if(keyStore == null) keyStore = Paths.get(System.getProperty("user.home"), "keystore");
         if(keyStore.equals(NONE)) {
            store.load(() -> storePass);
         } else if(Files.exists(keyStore)) {
            try(InputStream input = Files.newInputStream(keyStore)) {
               store.load(input, (storePass != null) ? storePass.getPassword() : null);
            }
         } else {
            throw new NoSuchFileException("No keystore file could be found");
         }

         KeyStore.PasswordProtection pass = (keyPass != null) ? keyPass : storePass;
         KeyStore.Entry entry = store.getEntry(alias, pass);
         if(!(entry instanceof KeyStore.PrivateKeyEntry)) {
            throw new UnrecoverableKeyException(String.format("Alias %s entry is not a PrivateKey entry", alias));
         }
         KeyStore.PrivateKeyEntry priKeyEntry = (KeyStore.PrivateKeyEntry) entry;

         CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
         List<X509Certificate> chain = null;
         if(certChain != null) {
            try(InputStream input = Files.newInputStream(certChain)) {
               Collection<? extends Certificate> certs = certificateFactory.generateCertificates(input);
               chain = certs.stream()
                       .map(cert -> (X509Certificate) cert)
                       .collect(Collectors.toList());
            }
         } else {
            List<Certificate> certs = Arrays.asList(priKeyEntry.getCertificateChain());
            chain = certs.stream()
                                .map(cert -> (X509Certificate) cert)
                                .collect(Collectors.toList());
         }


         if(chain.isEmpty()) {
            throw new CertificateException("No signing certificate found");
         }


         if(strict) {
            if(trustStore == null) trustStore = TrustStore.Builder.create().build();
            trustStore.validate(chain, KeyUsage.CodeSigning);
         }

         PrivateKey privateKey = priKeyEntry.getPrivateKey();

         final List<X509Certificate> certChain = chain;
         return new Identity() {
            @Override
            public String getName()
            {
               return alias;
            }

            @Override
            public PrivateKey getPrivateKey()
            {
               return privateKey;
            }

            @Override
            public X509Certificate getCertificate()
            {
               return certChain.get(0);
            }

            @Override
            public X509Certificate[] getCertificateChain()
            {
               return certChain.toArray(new X509Certificate[0]);
            }

            @Override
            public String toString() { return String.format("%s (%s)", alias, privateKey.getAlgorithm()); }
         };
      } finally {
         destroy(storePass);
         destroy(keyPass);
      }
   }



   private Path validate(Path path, String ident)
      throws NoSuchFileException
   {
      if(path != null && (!Files.exists(path) || !Files.isReadable(path))) {
         throw new NoSuchFileException(String.format("%s %s not found or is unreadable", ident, path));
      }
      return path;
   }

   private KeyStore createKeyStoreInstance()
      throws KeyStoreException
   {
      String type = (storeType != null) ? storeType : KeyStore.getDefaultType();
      if(provider != null) return KeyStore.getInstance(type, provider);
      return KeyStore.getInstance(type);
   }



   private static void destroy(KeyStore.PasswordProtection passwd)
   {
      try {
         passwd.destroy();
      } catch(Exception e) {
         /* Ignore */
      }
   }



}
