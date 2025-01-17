package org.xpertss.jarsigner;

import java.security.KeyStore;

public class TrustStore {

    // Note we may have a separate certificate Chain file specified.
    // loading done in getAliasInfo method of Main.java

    CertificateFactory certificateFactory;
    CertPathValidator validator;
    PKIXParameters pkixParameters;

    /*
      Loads the TrustedKeyStore and adds the trusted certs
      Loads the KeyStore (adds to trusted certs and the signing cert (if self-signed))
     */



    // Maybe our getters should be getJarSignerBuilder(String alias)
    // And it gets the CertChain and PrivateKey
    // validateCertChain methods in Main.java

    public KeyStore getKeyStore()
    {
        return null;
    }


    public PKIXParameters getPkixParameters()
    {
        return null;
    }

    // TODO builder with -keystore, -storetype, -storepass, -keypass, -certfile, Provider
}
