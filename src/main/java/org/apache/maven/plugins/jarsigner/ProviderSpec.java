package org.apache.maven.plugins.jarsigner;

import org.apache.maven.shared.utils.StringUtils;

/**
 * Parameter spec identifying a Java Security provider to install from the current classpath and it's
 * optional instantiation argument. Each provider will be instantiated and installed into Java's
 * provider set upon launch.
 */
public class ProviderSpec {

    /**
     * The fully qualified classname of the Provider to instantiate.
     */
    private String classname;

    /**
     * An argument to init the newly loaded Provider with.
     */
    private String argument;


    

    public String getClassName()
    {
        return classname;
    }

    public void setClassName(String classname)
    {
        this.classname = classname;
    }


    public String getArgument()
    {
        return argument;
    }

    public void setArgument(String argument)
    {
        this.argument = argument;
    }



    @Override
    public String toString()
    {
        StringBuilder builder = new StringBuilder();
        if(StringUtils.isNotEmpty(classname))
            builder.append(String.format("classname=%s", classname));
        if(StringUtils.isNotEmpty(argument)) {
            if (builder.length() > 0) builder.append(", ");
            builder.append(String.format("argument=%s", argument));
        }
        return builder.insert(0, "{").append("}").toString();
    }


}
