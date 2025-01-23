package org.apache.maven.plugins.jarsigner;

import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.shared.utils.StringUtils;

public class ProviderSpec {

    /**
     * See <a href="https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    @Parameter(property = "jarsigner.provider.providerClass")
    private String providerClass;

    /**
     * See <a href="https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    @Parameter(property = "jarsigner.provider.providerArg")
    private String providerArg;


    public String getProviderClass()
    {
        return providerClass;
    }

    public void setProviderClass(String providerClass)
    {
        this.providerClass = providerClass;
    }


    public String getProviderArg()
    {
        return providerArg;
    }

    public void setProviderArg(String providerArg)
    {
        this.providerArg = providerArg;
    }

    @Override
    public String toString()
    {
        StringBuilder builder = new StringBuilder();
        if(StringUtils.isNotEmpty(providerClass))
            builder.append(String.format("providerClass=%s", providerClass));
        if(StringUtils.isNotEmpty(providerArg)) {
            if (builder.length() > 0) builder.append(", ");
            builder.append(String.format("providerArg=%s", providerArg));
        }
        return builder.insert(0, "{").append("}").toString();
    }


}
