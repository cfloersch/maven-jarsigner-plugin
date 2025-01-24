package org.apache.maven.plugins.jarsigner;

import org.apache.maven.shared.utils.StringUtils;

import java.io.File;

public class KeyStoreSpec {

    // NOTE: No point in using @Parameter annotations as they are not used

    private File path;
    private String storepass;
    private String storetype;
    private String provider;


    public String getStorePass()
    {
        return storepass;
    }

    public void setStorePass(String storepass)
    {
        this.storepass = storepass;
    }


    public File getPath()
    {
        return path;
    }

    public void setPath(File path)
    {
        this.path = path;
    }


    public String getStoreType()
    {
        return storetype;
    }

    public void setStoreType(String storetype)
    {
        this.storetype = storetype;
    }


    public String getProvider()
    {
        return provider;
    }

    public void setProvider(String provider)
    {
        this.provider = provider;
    }



    @Override
    public String toString()
    {
        StringBuilder builder = new StringBuilder();
        if(path != null)
            builder.append(String.format("path=%s", path));
        if(StringUtils.isNotEmpty(storetype)) {
            if(builder.length() > 0) builder.append(", ");
            builder.append(String.format("storetype=%s", storetype));
        }
        if(StringUtils.isNotEmpty(storepass)) {
            if(builder.length() > 0) builder.append(", ");
            builder.append(String.format("storepass=%s", storepass));
        }
        if(StringUtils.isNotEmpty(provider)) {
            if(builder.length() > 0) builder.append(", ");
            builder.append(String.format("provider=%s", provider));
        }
        return builder.insert(0, "{").append("}").toString();
    }

}
