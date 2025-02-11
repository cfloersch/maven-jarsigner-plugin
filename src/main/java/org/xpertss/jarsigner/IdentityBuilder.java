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
import java.security.GeneralSecurityException;
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
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.function.Function;
import java.util.function.Predicate;
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

   private Path trustStore;
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
    * Specify a path to a trust store file from which trusted certificates can be loaded.
    * <p/>
    * This must point at a JKS keystore that contains trusted certificates accessible.
    *
    * @param trustStore Path to the trust store file
    * @throws NoSuchFileException If the path does not exist or is not readable.
    */
   public IdentityBuilder trustStore(Path trustStore)
      throws NoSuchFileException
   {
      this.trustStore = validate(trustStore, "Truststore");
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
         CertPath cp = null;
         if(certChain != null) {
            try(InputStream input = Files.newInputStream(certChain)) {
               Collection<? extends Certificate> certs = certificateFactory.generateCertificates(input);
               List<Certificate> certificates = new ArrayList<>(certs);
               cp = certificateFactory.generateCertPath(certificates);
            }
         } else {
            List<Certificate> certificates = Arrays.asList(priKeyEntry.getCertificateChain());
            cp = certificateFactory.generateCertPath(certificates);
         }

         if(cp.getCertificates().isEmpty()) {
            throw new CertificateException("No signing certificate found");
         }


         if(strict) {
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            PKIXParameters pkixParameters = new PKIXParameters(createTrustAnchorSet(store, trustStore));
            pkixParameters.setRevocationEnabled(false);
            pkixParameters.setTargetCertConstraints(new CodeSigningCertSelector());
            validator.validate(cp, pkixParameters);
         }

         PrivateKey privateKey = priKeyEntry.getPrivateKey();

         List<X509Certificate> chain = cp.getCertificates().stream()
                                            .map(cert -> (X509Certificate) cert)
                                            .collect(Collectors.toList());

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
               return chain.get(0);
            }

            @Override
            public X509Certificate[] getCertificateChain()
            {
               return chain.toArray(new X509Certificate[0]);
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

   private Set<TrustAnchor> createTrustAnchorSet(KeyStore keystore, Path trustStore)
      throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException
   {
      Set<TrustAnchor> tas = new LinkedHashSet<>();
      try {
         KeyStore caks = getTrustStore(trustStore);
         add(caks, Objects::nonNull, tas);
      } catch (GeneralSecurityException | IOException  e) {
         // Ignore, if cacerts cannot be loaded
         if(trustStore != null) throw e;
      }
      add(keystore, cert -> cert.getSubjectDN().equals(cert.getIssuerDN()), tas);
      return tas ;
   }


   private static void add(KeyStore store, Predicate<X509Certificate> filter, Set<TrustAnchor> tas)
   {
      try {
         Enumeration<String> aliases = store.aliases();
         while(aliases.hasMoreElements()) {
            String a = aliases.nextElement();
            try {
               X509Certificate c = (X509Certificate) store.getCertificate(a);
               if(filter.test(c) || store.isCertificateEntry(a)) {
                  tas.add(new TrustAnchor(c, null));
               }
            } catch(Exception e2) {
               // ignore, when an Entry does not include a cert
            }
         }
      } catch(Exception e) { /* Ignore */ }
   }

   /**
    * Returns the keystore with the configured CA certificates.
    */
   public static KeyStore getTrustStore(Path trustStore)
      throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException
   {
      if(trustStore == null) {
         trustStore = Paths.get(System.getProperty("java.home"), "lib", "security", "cacerts");
      }
      if(!Files.exists(trustStore)) return null;
      try(InputStream in = Files.newInputStream(trustStore)) {
         KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
         store.load(in, null);
         return store;
      }
   }


   private static void destroy(KeyStore.PasswordProtection passwd)
   {
      try {
         passwd.destroy();
      } catch(Exception e) {
         /* Ignore */
      }
   }



   public static class CodeSigningCertSelector implements CertSelector {

      @Override
      public boolean match(Certificate cert)
      {
         if (cert instanceof X509Certificate) {
            X509Certificate xcert = (X509Certificate)cert;
            return isSignatureOrNonRepudiation(xcert)
                     && isAnyOrCodeSigning(xcert);
         }
         return false;
      }

      @Override
      public Object clone()
      {
         try {
            return super.clone();
         } catch(CloneNotSupportedException e) {
            throw new InternalError(e.toString(), e);
         }
      }

      private boolean isSignatureOrNonRepudiation(X509Certificate xcert)
      {
         boolean[] keyUsage = xcert.getKeyUsage();
         if (keyUsage != null) {
            keyUsage = Arrays.copyOf(keyUsage, 9);
            return keyUsage[0] || keyUsage[1];
         }
         return true;
      }

      private boolean isAnyOrCodeSigning(X509Certificate userCert)
      {
         try {
            List<String> xKeyUsage = userCert.getExtendedKeyUsage();
            if (xKeyUsage != null) {
               if (!xKeyUsage.contains("2.5.29.37.0") // anyExtendedKeyUsage
                  && !xKeyUsage.contains("1.3.6.1.5.5.7.3.3")) {  // codeSigning
                  return false;
               }
            }
         } catch (java.security.cert.CertificateParsingException e) {
            return false;
         }
         return true;
      }

   }
}
