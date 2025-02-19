package org.xpertss.crypto.utils;


import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertPath;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;


import static org.junit.jupiter.api.Assertions.*;

class CertOrderTest {

    @Test
    public void testNullIsThrown()
    {
        CertPath certPath = null;
        assertThrows(NullPointerException.class, () -> {
            CertOrder.of(certPath);
        });
    }

    @Test
    public void testIllegalArgumentIsThrown()
    {
        assertThrows(IllegalArgumentException.class, () -> {
            CertOrder.of(new X509Certificate[0]);
        });
    }

    @Test
    public void testIllegalArgumentIsThrownTwo()
    {
        assertThrows(IllegalArgumentException.class, () -> {
            CertOrder.of();
        });
    }


    @Test
    public void testPkcs7Ordering() throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X509");
        Path path = Paths.get("src", "test", "resources", "certs", "server-cert-path.crt");
        try(InputStream in = Files.newInputStream(path)) {
            CertPath certPath = factory.generateCertPath(in, "PKCS7");
            assertEquals(CertOrder.Reverse, CertOrder.of(certPath));
        }
    }

    @Test
    public void testChainOrdering() throws Exception {
        X509Certificate[] chain = loadChain();
        assertEquals(CertOrder.Forward, CertOrder.of(chain));
    }

    @Test
    public void testReOrdering() throws Exception
    {
        CertificateFactory factory = CertificateFactory.getInstance("X509");
        Path path = Paths.get("src", "test", "resources", "certs", "server-cert-path.crt");
        try(InputStream in = Files.newInputStream(path)) {
            CertPath certPath = factory.generateCertPath(in, "PKCS7");
            assertEquals(CertOrder.Reverse, CertOrder.of(certPath));
            CertPath copy = CertOrder.Forward.convertTo(certPath);
            assertEquals(CertOrder.Forward, CertOrder.of(copy));
        }
    }

    @Test
    public void testReOrderingUnnecessary_onArray() throws Exception
    {
        X509Certificate[] chain = loadChain();
        X509Certificate[] ordered = CertOrder.Forward.convertTo(chain);
        assertSame(chain, ordered);
    }

    @Test
    public void testReOrderingUnnecessary_onPath() throws Exception
    {
        CertificateFactory factory = CertificateFactory.getInstance("X509");
        Path path = Paths.get("src", "test", "resources", "certs", "server-cert-path.crt");
        try(InputStream in = Files.newInputStream(path)) {
            CertPath certPath = factory.generateCertPath(in, "PKCS7");
            CertPath ordered = CertOrder.Reverse.convertTo(certPath);
            assertSame(certPath, ordered);
        }
    }

    @Test
    public void testReOrderingUnnecessary_onList() throws Exception
    {
        CertificateFactory factory = CertificateFactory.getInstance("X509");
        Path path = Paths.get("src", "test", "resources", "certs", "server-cert-path.crt");
        try(InputStream in = Files.newInputStream(path)) {
            CertPath certPath = factory.generateCertPath(in, "PKCS7");
            X509Certificate[] chain = CertificateUtils.toX509Chain(certPath);
            List<X509Certificate> certs = Arrays.asList(chain);
            List<X509Certificate> ordered = CertOrder.Reverse.convertTo(certs);
            assertSame(certs, ordered);
        }
    }


    @Test
    public void testTrustAnchor() throws Exception
    {
        X509Certificate[] chain = loadChain();
        assertEquals(CertOrder.Reverse, CertOrder.of(chain[2]));
    }

    @Test
    public void testEndEntity() throws Exception
    {
        X509Certificate[] chain = loadChain();
        assertEquals(CertOrder.Forward, CertOrder.of(chain[0]));
    }

    @Test
    public void testIntermediary() throws Exception
    {
        X509Certificate[] chain = loadChain();
        assertEquals(CertOrder.Forward, CertOrder.of(chain[1]));
    }

    @Test
    public void testEndAndIntermediary() throws Exception
    {
        X509Certificate[] chain = loadChain();
        assertEquals(CertOrder.Forward, CertOrder.of(Arrays.copyOf(chain, 2)));
    }


    @Test
    public void testReverseNoTrustAnchor() throws Exception
    {
        X509Certificate[] chain = loadChain();
        X509Certificate[] copy = new X509Certificate[2];
        copy[0] = chain[1];
        copy[1] = chain[0];
        assertEquals(CertOrder.Reverse, CertOrder.of(copy));
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