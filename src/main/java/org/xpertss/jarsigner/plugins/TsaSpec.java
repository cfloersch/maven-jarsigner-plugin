package org.xpertss.jarsigner.plugins;

import org.codehaus.plexus.util.StringUtils;


/**
 * Simple Mojo property holder for Time Stamp Authority configuration.
 */
public class TsaSpec {

    private String uri;     // TODO Can I make this type URI??
    private String policyId;
    private String digestAlg;


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




    @Override
    public String toString()
    {
        StringBuilder builder = new StringBuilder();
        if(StringUtils.isNotEmpty(uri))
            builder.append(String.format("uri=%s", uri));
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
