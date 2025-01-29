package org.xpertss.jarsigner;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

@Disabled
public class JavaManifestTest {

    @Test
    public void testManifest_InvalidVersion() throws Exception
    {
        Manifest manifest = new Manifest();
        try(InputStream in = load("CORRUPT.MF")) {
            manifest.read(in);
        }
        Attributes attributes = manifest.getMainAttributes();
        assertEquals("1.0", attributes.get("Manifest-Version"));
    }

    @Test
    public void testManifest_InvalidName() throws Exception
    {
        Manifest manifest = new Manifest();
        try(InputStream in = load("INVALID_NAME.MF")) {
            manifest.read(in);
        }
        Attributes attributes = manifest.getMainAttributes();
        assertEquals("1.0", attributes.get("Manifest-Version"));
    }

    @Test
    public void testManifest_Garbage() throws Exception
    {
        Manifest manifest = new Manifest();
        try(InputStream in = load("GARBAGE.MF")) {
            manifest.read(in);
        }
        Attributes attributes = manifest.getMainAttributes();
        assertEquals("1.0", attributes.get("Manifest-Version"));
    }

    @Test
    public void testRegexPatternForName()
    {
        Pattern pattern = Pattern.compile("^[a-zA-Z0-9_-]*$");
        assertTrue(Pattern.matches("^[a-zA-Z0-9_-]*$", "HelloWorld"));
        assertTrue(Pattern.matches("^[a-zA-Z0-9_-]*$", "Hello-World"));
        assertTrue(Pattern.matches("^[a-zA-Z0-9_-]*$", "Hello_World"));
        assertTrue(Pattern.matches("^[a-zA-Z0-9_-]*$", "HelloWorld2"));
        assertTrue(Pattern.matches("^[a-zA-Z0-9_-]*$", "Name"));

        assertFalse(Pattern.matches("^[a-zA-Z0-9_-]*$", "Hello World"));
        assertFalse(Pattern.matches("^[a-zA-Z0-9_-]*$", "HelloWorld!"));
        assertFalse(Pattern.matches("^[a-zA-Z0-9_-]*$", "HelloWorld#"));
        assertFalse(Pattern.matches("^[a-zA-Z0-9_-]*$", "HelloWorld@"));
        assertFalse(Pattern.matches("^[a-zA-Z0-9_-]*$", "HelloWorld$"));
    }


    private static InputStream load(String file) throws Exception
    {
        Path manifestPath = Paths.get("src","test", "resources", file);
        return Files.newInputStream(manifestPath);
    }
}
