package org.xpertss.crypto.utils;

import java.security.cert.CertPath;
import java.security.cert.X509Certificate;

public final class CertificateUtils {

    private CertificateUtils() { }

    /**
     * Returns {@code true} if the subject distinguished name is equal to the
     * issuer distinguished name, {@code false} otherwise.
     *
     * @param cert The certificate to inspect
     */
    public static boolean isSelfSigned(X509Certificate cert)
    {
        return cert.getSubjectDN().equals(cert.getIssuerDN());
    }

    /**
     * Streams through the certificates in the {@link CertPath} converting them
     * to X509Certificates, and then collecting them into an array to return.
     *
     * @param certPath The certificate path to convert
     * @throws ClassCastException if the certificates are not X509
     */
    public static X509Certificate[] toX509Chain(CertPath certPath)
    {
        return certPath.getCertificates().stream()
                        .map(cert -> (X509Certificate) cert)
                        .toArray(X509Certificate[]::new);

    }

}
