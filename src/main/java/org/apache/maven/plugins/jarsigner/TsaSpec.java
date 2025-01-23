package org.apache.maven.plugins.jarsigner;

import org.apache.maven.plugins.annotations.Parameter;
import org.codehaus.plexus.util.StringUtils;

public class TsaSpec {

    @Parameter(required = false)
    private String cert;

    @Parameter(required = false)
    private String uri;

    @Parameter(required = false)
    private String policyId;

    @Parameter(required = false)
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

    public boolean isNull()
    {
        return isEmpty(uri) && isEmpty(cert) && isEmpty(digestAlg) && isEmpty(policyId);
    }

    public int validCount()
    {
        int count = 0;
        if(!isEmpty(uri)) count++;
        if(!isEmpty(cert)) count++;
        return count;
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


    private static boolean isEmpty(String str)
    {
        return str == null || str.isEmpty();
    }

}
