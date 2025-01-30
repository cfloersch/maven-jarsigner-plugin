package org.xpertss.jarsigner;

import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;

class TsaSignerTest {

    @Test
    public void testToStringFull() throws Exception
    {
        TsaSigner signer = TsaSigner.Builder.of(URI.create("https://tsa.openworld.com/tsa"))
                                    .policyId("0.0").digestAlgorithm("SHA-256").build();
        assertEquals("[uri=https://tsa.openworld.com/tsa, policyId=0.0, digest=SHA-256]", signer.toString());
    }

    @Test
    public void testToStringShort() throws Exception
    {
        TsaSigner signer = TsaSigner.Builder.of(URI.create("https://tsa.openworld.com/tsa")).build();
        assertEquals("[uri=https://tsa.openworld.com/tsa]", signer.toString());
    }

}