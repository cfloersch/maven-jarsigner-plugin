package org.apache.maven.plugins.jarsigner;

import org.codehaus.plexus.util.StringUtils;
import org.xpertss.jarsigner.TsaSigner;

import java.net.URI;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class TsaSpec {

    private String cert;
    private String uri;
    private String policyId;
    private String digestAlg;


    public String getCert()
    {
        return cert;
    }

    public void setCert(String cert)
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
        if(StringUtils.isNotEmpty(cert)) count++;
        return count;
    }


    public TsaSigner build()
       throws CertificateException
    {
        if(cert != null) {
            // preferred path
        } else if(uri != null) {

        }
        return null;
    }




    @Override
    public String toString()
    {
        StringBuilder builder = new StringBuilder();
        if(StringUtils.isNotEmpty(uri))
            builder.append(String.format("uri=%s", uri));
        if(StringUtils.isNotEmpty(cert)) {
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
