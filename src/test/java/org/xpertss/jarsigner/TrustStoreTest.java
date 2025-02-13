package org.xpertss.jarsigner;

import org.junit.jupiter.api.Test;

import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

class TrustStoreTest {

    @Test
    public void testTrustStorePath()
        throws Exception
    {
        TrustStore.Builder builder = TrustStore.Builder.create();
        builder.trustStore(Paths.get("src", "test", "truststore"));
    }

    @Test
    public void testTrustStoreNONEPath()
        throws Exception
    {
        TrustStore.Builder builder = TrustStore.Builder.create();
        assertThrows(NoSuchFileException.class, ()->{
            builder.trustStore(Paths.get("NONE"));
        });
    }

    @Test
    public void testTrustStoreClearPath()
        throws Exception
    {
        TrustStore.Builder builder = TrustStore.Builder.create();
        builder.trustStore(null);
    }

    @Test
    public void testTrustStoreDoesNotExistPath()
            throws Exception
    {
        TrustStore.Builder builder = TrustStore.Builder.create();
        assertThrows(NoSuchFileException.class, ()->{
            builder.trustStore(Paths.get("does", "not", "exist"));
        });
    }


}