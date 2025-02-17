package org.xpertss.jarsigner;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertPath;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;


import static org.junit.jupiter.api.Assertions.*;

class CertOrderingTest {

    @Test
    public void testNullIsThrown()
    {
        CertPath certPath = null;
        assertThrows(NullPointerException.class, () -> {
            CertOrdering.of(certPath);
        });
    }

    @Test
    public void testIllegalArgumentIsThrown()
    {
        assertThrows(IllegalArgumentException.class, () -> {
            CertOrdering.of(new X509Certificate[0]);
        });
    }

    @Test
    public void testIllegalArgumentIsThrownTwo()
    {
        assertThrows(IllegalArgumentException.class, () -> {
            CertOrdering.of();
        });
    }


    @Test
    public void testPkcs7Ordering() throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X509");
        Path path = Paths.get("src", "test", "resources", "certs", "server-cert-path.crt");
        try(InputStream in = Files.newInputStream(path)) {
            CertPath certPath = factory.generateCertPath(in, "PKCS7");
            assertEquals(CertOrdering.Reverse, CertOrdering.of(certPath));
        }
    }

    @Test
    public void testChainOrdering() throws Exception {
        X509Certificate[] chain = loadChain();
        assertEquals(CertOrdering.Forward, CertOrdering.of(chain));
    }

    @Test
    public void testReOrdering() throws Exception
    {
        CertificateFactory factory = CertificateFactory.getInstance("X509");
        Path path = Paths.get("src", "test", "resources", "certs", "server-cert-path.crt");
        try(InputStream in = Files.newInputStream(path)) {
            CertPath certPath = factory.generateCertPath(in, "PKCS7");
            assertEquals(CertOrdering.Reverse, CertOrdering.of(certPath));
            CertPath copy = CertOrdering.Forward.convertTo(certPath);
            assertEquals(CertOrdering.Forward, CertOrdering.of(copy));
        }
    }

    @Test
    public void testTrustAnchor() throws Exception
    {
        X509Certificate[] chain = loadChain();
        assertEquals(CertOrdering.Reverse, CertOrdering.of(chain[2]));
    }

    @Test
    public void testEndEntity() throws Exception
    {
        X509Certificate[] chain = loadChain();
        assertEquals(CertOrdering.Forward, CertOrdering.of(chain[0]));
    }

    @Test
    public void testIntermediary() throws Exception
    {
        X509Certificate[] chain = loadChain();
        assertEquals(CertOrdering.Forward, CertOrdering.of(chain[1]));
    }

    @Test
    public void testEndAndIntermediary() throws Exception
    {
        X509Certificate[] chain = loadChain();
        assertEquals(CertOrdering.Forward, CertOrdering.of(Arrays.copyOf(chain, 2)));
    }


    @Disabled
    @Test
    public void testReverseNoTrustAnchor() throws Exception
    {
        // TODO Fix this
        X509Certificate[] chain = loadChain();
        X509Certificate[] copy = new X509Certificate[2];
        copy[0] = chain[1];
        copy[1] = chain[0];
        assertEquals(CertOrdering.Reverse, CertOrdering.of(copy));
    }



    private X509Certificate[] loadChain() throws Exception
    {
        CertificateFactory factory = CertificateFactory.getInstance("X509");
        Path path = Paths.get("src", "test", "resources", "certs", "server-cert-chain.pem");
        try(InputStream in = Files.newInputStream(path)) {
            return factory.generateCertificates(in)
                    .stream()
                    .map(cert -> (X509Certificate) cert)
                    .toArray(X509Certificate[]::new);
        }
    }

}