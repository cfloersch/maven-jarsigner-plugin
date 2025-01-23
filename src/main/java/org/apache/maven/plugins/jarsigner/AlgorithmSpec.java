package org.apache.maven.plugins.jarsigner;

import org.apache.maven.shared.utils.StringUtils;


public class AlgorithmSpec {

    private String algorithm;
    private String provider;

    public String getAlgorithm()
    {
        return algorithm;
    }

    public void setAlgorithm(String algorithm)
    {
        this.algorithm = algorithm;
    }

    public String getProvider()
    {
        return provider;
    }

    public void setProvider(String provider)
    {
        this.provider = provider;
    }

    public boolean isNull()
    {
        return StringUtils.isEmpty(algorithm)
                    && StringUtils.isEmpty(provider);
    }

    @Override
    public String toString()
    {
        StringBuilder builder = new StringBuilder();
        if(StringUtils.isNotEmpty(algorithm))
            builder.append(String.format("algorithm=%s", algorithm));
        if(StringUtils.isNotEmpty(provider)) {
            if (builder.length() > 0) builder.append(", ");
            builder.append(String.format("provider=%s", provider));
        }
        return builder.insert(0,"{").append("}").toString();
    }

}
