package org.xpertss.jarsigner;

import java.security.cert.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Enumeration of possible certificate chain and certificate path orderings.
 */
public enum CertOrdering {

    /**
     * Forward ordering is from end-entity -> trust anchor
     */
    Forward,

    /**
     * Reverse ordering is from trust anchor -> end-entity
     */
    Reverse,

    /**
     * If a single cert is supplied
     */
    Unknown;


    /**
     * Utility method to convert the given certificate path to this ordering. If the
     * certificate path ordering is already compliant this simply returns it, otherwise
     * a new CertPath is created and returned.
     *
     * @param certPath The certificate path to re-order
     * @throws CertificateException If the cert path is of an unsupported type or if
     *      generating a reversed cert path
     */
    public CertPath convertTo(CertPath certPath)
        throws CertificateException
    {
        CertOrdering ordering = of(certPath);
        if(ordering != this) {
            List<? extends Certificate> copy = new ArrayList<>(certPath.getCertificates());
            Collections.reverse(copy);
            CertificateFactory factory = CertificateFactory.getInstance(certPath.getType());
            return factory.generateCertPath(copy);
        }
        return certPath;
    }

    /**
     * Utility method to convert the given certificate chain to this ordering. If the
     * certificate chain ordering is already compliant this simply returns the given
     * array, otherwise a new array is created and returned.

     * @param chain The certificate chain to re-order
     */
    public X509Certificate[] convertTo(X509Certificate ... chain)
    {
        CertOrdering ordering = of(chain);
        if(ordering != this) {
            return convertTo(Arrays.asList(chain))
                        .toArray(new X509Certificate[0]);
        }
        return chain;
    }



    /**
     * Utility method to convert the given certificate chain to this ordering. If the
     * certificate chain ordering is already compliant this simply returns the given
     * list, otherwise a new list is created and returned.

     * @param chain The certificate chain to re-order
     */
    public List<X509Certificate> convertTo(List<X509Certificate> chain)
    {
        CertOrdering ordering = of(chain);
        if(ordering != this) {
            List<X509Certificate> copy = new ArrayList<>(chain);
            Collections.reverse(copy);
            return copy;
        }
        return chain;
    }





    // TODO What to do if they supply a single cert?
    //  If self signed we can say Reverse?
    //  If not self signed we say Forward?

    /**
     * A utility method to determine the current ordering of the supplied certificate path.
     *
     * @param certPath The path to determine ordering of
     */
    public static CertOrdering of(CertPath certPath)
    {
        return of(certPath.getCertificates().stream()
                .map(cert -> (X509Certificate) cert)
                .toArray(X509Certificate[]::new));
    }

    /**
     * A utility method to determine the current ordering of the supplied certificate chain.
     *
     * @param chain The chain to determine ordering of
     */
    public static CertOrdering of(X509Certificate... chain)
    {
        if(chain.length == 0)
            throw new IllegalArgumentException("No chain presented");
        // TODO if element at 0 is not self signed we need to actually dig in
        //  test the ordering based on issuer/subject chain
        //  There is one more short cut (if chain.length -1 == selfSigned we are for sure Forward)
        if(isSelfSigned(chain[0])) {
            return Reverse;
        } else if(chain.length > 1) {
            if(isSelfSigned(chain[chain.length - 1])) {
                return Forward;
            } else {
                // TODO Do the magic here
            }
        }
        return Forward;
    }


    /**
     * A utility method to determine the current ordering of the supplied certificate chain.
     *
     * @param chain The chain to determine ordering of
     */
    public static CertOrdering of(List<X509Certificate> chain)
    {
        return of(chain.toArray(new X509Certificate[0]));
    }


    private static boolean isSelfSigned(X509Certificate cert)
    {
        return cert.getSubjectDN().equals(cert.getIssuerDN());
    }
}
