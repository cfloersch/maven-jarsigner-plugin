package org.xpertss.jarsigner;

import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

public enum KeyUsage {

    CodeSigning(CertConstraint.codeSigning()),

    Timestamping(CertConstraint.timeStamping());

    private CertSelector selector;

    private KeyUsage(CertSelector selector)
    {
        this.selector = selector;
    }

    public CertSelector getConstraints()
    {
        return selector;
    }



    private static class CertConstraint implements CertSelector {

        public static CertConstraint codeSigning()
        {
            return new CertConstraint("1.3.6.1.5.5.7.3.3");
        }

        public static CertConstraint timeStamping()
        {
            return new CertConstraint("1.3.6.1.5.5.7.3.8");
        }


        private String extUsageOid;

        private CertConstraint(String oid)
        {
            this.extUsageOid = oid;
        }


        @Override
        public boolean match(Certificate cert)
        {
            if (cert instanceof X509Certificate) {
                X509Certificate xcert = (X509Certificate)cert;
                return isSignatureOrNonRepudiation(xcert)
                        && isGoodExtendedUsage(xcert);
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

        private boolean isGoodExtendedUsage(X509Certificate userCert)
        {
            try {
                List<String> xKeyUsage = userCert.getExtendedKeyUsage();
                if (xKeyUsage != null) {
                    if (!xKeyUsage.contains("2.5.29.37.0") // anyExtendedKeyUsage
                            && !xKeyUsage.contains(extUsageOid)) {  // codeSigning
                        return false;
                    }
                }
            } catch (CertificateParsingException e) {
                return false;
            }
            return true;
        }

    }


}
