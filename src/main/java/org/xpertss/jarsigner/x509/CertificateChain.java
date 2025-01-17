package org.xpertss.jarsigner.x509;


import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.util.Set;

/*
   Maybe this just certifies the Signing cert itself?
   The chain of trust is validated using CertPathValidator which is part of TrustStore
 */
public class CertificateChain {


    public CertificateChain(CertPath certPath)
    {
    }


    public X509Certificate getSubjectCertificate()
    {
        return null;
    }




    public Set<ChainIssue> validateChain()
    {
        return null;
    }

}
