package org.xpertss.jarsigner.plugins;

import java.security.Provider;

public class TestProvider extends Provider {
    /**
     * Constructs a provider with the specified name, version number,
     * and information.
     */
    public TestProvider(String config) {
        super("TestProv", 1.0, "AWS KMS Provider");
    }
}
