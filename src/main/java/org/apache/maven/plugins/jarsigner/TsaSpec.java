package org.apache.maven.plugins.jarsigner;

import org.codehaus.plexus.util.StringUtils;
import org.xpertss.jarsigner.TsaSigner;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

public class TsaSpec {

    private File cert;
    private String uri;     // TODO Can I make this type URI??
    private String policyId;
    private String digestAlg;


    public File getCert()
    {
        return cert;
    }

    public void setCert(File cert)
    {
        this.cert = cert;
    }


    public String getUri()
    {
        return uri;
    }

    public void setUri(String uri)
    {
        this.uri = uri;
    }


    public String getPolicyId()
    {
        return policyId;
    }

    public void setPolicyId(String policyId)
    {
        this.policyId = policyId;
    }


    public String getDigestAlg()
    {
        return digestAlg;
    }

    public void setDigestAlg(String digestAlg)
    {
        this.digestAlg = digestAlg;
    }


    public int validCount()
    {
        int count = 0;
        if(StringUtils.isNotEmpty(uri)) count++;
        if(cert != null) count++;
        return count;
    }


    public TsaSigner build()
        throws IOException, CertificateException,
                NoSuchProviderException, NoSuchAlgorithmException
    {
        TsaSigner.Builder builder = null;
        if(cert != null) {
            CertificateFactory certFactory = CertificateFactory.getInstance("X509");
            try(InputStream in = Files.newInputStream(cert.toPath())) {
                Certificate xcert = certFactory.generateCertificate(in);
                builder = TsaSigner.Builder.of(xcert).digestAlgorithm(digestAlg);
                if(StringUtils.isNotEmpty(policyId)) builder.policyId(policyId);
            }
        } else if(uri != null) {
            builder = TsaSigner.Builder.of(URI.create(uri))
                            .digestAlgorithm(digestAlg).policyId(policyId);
        }
        return (builder != null) ? builder.build() : null;
    }




    @Override
    public String toString()
    {
        StringBuilder builder = new StringBuilder();
        if(StringUtils.isNotEmpty(uri))
            builder.append(String.format("uri=%s", uri));
        if(cert != null) {
            if(builder.length() > 0) builder.append(", ");
            builder.append(String.format("cert=%s", cert));
        }
        if(StringUtils.isNotEmpty(digestAlg)) {
            if(builder.length() > 0) builder.append(", ");
            builder.append(String.format("digest=%s", digestAlg));
        }
        if(StringUtils.isNotEmpty(policyId)) {
            if(builder.length() > 0) builder.append(", ");
            builder.append(String.format("policyId=%s", policyId));
        }
        return builder.insert(0, "{").append("}").toString();
    }


}
