/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 1/19/2025
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
import java.security.cert.*;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * This object is used as a store for trusted certificates. That is important any time
 * a certificate chain must be validated. This includes signature verifications as well
 * as Identity and Timestamp Authority validation when signing with {@code strict}.
 */
public class TrustStore {

    private KeyStore trustStore;
    private PKIXParameters parameters;


    private TrustStore(KeyStore trustStore, PKIXParameters parameters)
    {
        this.trustStore = trustStore;
        this.parameters = parameters;
    }


    // TODO Other methods here


    /**
     * Validate the given certificate chain. Key Usage will indicate within what context the
     * validation is being done. The two options are code signing and timestamping.
     *
     * @param chain The certificate chain to validate.
     * @param keyUsage The primary key usage that should be checked.
     * @throws CertificateException If there is an issue with any of the input certificates
     * @throws CertPathValidatorException If the validation of the certificates fails.
     */
    public void validate(List<X509Certificate> chain, KeyUsage keyUsage)
        throws CertificateException, CertPathValidatorException
    {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            CertPath cp = factory.generateCertPath(chain);
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            parameters.setRevocationEnabled(false);
            parameters.setTargetCertConstraints(keyUsage.getConstraints());
            validator.validate(cp, parameters);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new CertPathValidatorException("Unable to perform certificate path validation", e);
        }
    }


    /**
     * Builder to construct a TrustStore.
     */
    public static class Builder {

        private Path trustStorePath;

        /**
         * Specify the trust store file to use. By default it will use the cacerts file
         * shipped with the core JRE.
         *
         * @param path The path to the trusted certs keystore file
         * @throws NoSuchFileException if the specified path references a non-existent file
         */
        public Builder trustStore(Path path)
            throws NoSuchFileException
        {
            if(path != null && (!Files.exists(path) || !Files.isReadable(path))) {
                throw new NoSuchFileException(String.format("truststore %s not found or is unreadable", path));
            }
            this.trustStorePath = path;
            return this;
        }

        /**
         * Create and return an instance of the TrustStore initialized with a given
         * underlying keystore.
         *
         * @throws KeyStoreException - If an error occurs loading the trusted keystore
         */
        public TrustStore build()
            throws KeyStoreException
        {
            try {
                KeyStore store = getTrustStore(trustStorePath);
                Enumeration<String> aliases = store.aliases();

                Set<TrustAnchor> tas = new LinkedHashSet<>();
                while (aliases.hasMoreElements()) {
                    String a = aliases.nextElement();
                    X509Certificate c = (X509Certificate) store.getCertificate(a);
                    if (c != null || store.isCertificateEntry(a)) {
                        tas.add(new TrustAnchor(c, null));
                    }
                }
                PKIXParameters pkixParameters = new PKIXParameters(tas);
                return new TrustStore(store, pkixParameters);
            } catch(InvalidAlgorithmParameterException e) {
                throw new KeyStoreException("Unable to initialize trust store", e);
            }
        }

        /**
         * Utility method to create an instance of the Builder.
         */
        public static Builder create()
        {
            return new Builder();
        }

    }



    /**
     * Returns the keystore with the configured CA certificates.
     */
    private static KeyStore getTrustStore(Path trustStore)
        throws KeyStoreException
    {
        if(trustStore == null) {
            trustStore = Paths.get(System.getProperty("java.home"), "lib", "security", "cacerts");
        }
        try(InputStream in = Files.newInputStream(trustStore)) {
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(in, null);
            return store;
        } catch(IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new KeyStoreException("Unable to load trust store " + trustStore);
        }
    }


}
