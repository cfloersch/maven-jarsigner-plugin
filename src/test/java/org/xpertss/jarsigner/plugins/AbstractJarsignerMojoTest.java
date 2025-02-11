package org.xpertss.jarsigner.plugins;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;
import org.apache.maven.settings.Proxy;
import org.apache.maven.settings.Settings;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcher;
import org.xpertss.jarsigner.tsa.AuthenticatedProxy;

import java.io.File;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;


import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AbstractJarsignerMojoTest {

    @Mock
    private MavenProject project;

    @Mock
    private SecDispatcher secDispatcher;

    @Mock
    private Settings settings;

    @Mock
    private MavenSession session;

    @Mock
    private Log log;

    private TestJarSignerMojo objectUnderTest;

    private Path target;

    @BeforeEach
    public void setUp(@TempDir Path tempDir)
        throws Exception
    {
        objectUnderTest = new TestJarSignerMojo(secDispatcher);
        objectUnderTest.setLog(log);

        setField(objectUnderTest, "settings", settings);
        setField(objectUnderTest, "session", session);
        setField(objectUnderTest, "project", project);
        setField(objectUnderTest, "workingDirectory", tempDir.toFile());

        Path src = Paths.get("src", "test", "javax.persistence_2.0.5.v201212031355.jar");
        target = tempDir.resolve("test.jar");
        Files.copy(src, target);
    }



    @Test
    public void testProvidersHappyPath() throws Exception
    {
        ProviderSpec[] specs = new ProviderSpec[1];
        specs[0] = new ProviderSpec();
        specs[0].setClassName("sun.security.provider.Sun");
        setField(objectUnderTest, "providers", specs);
        objectUnderTest.execute();
        verify(log, times(1)).info(eq("Provider SUN loaded."));
    }

    @Test
    public void testProviders_withArgument() throws Exception
    {
        ProviderSpec[] specs = new ProviderSpec[1];
        specs[0] = new ProviderSpec();
        specs[0].setClassName("org.xpertss.jarsigner.plugins.TestProvider");
        specs[0].setArgument("Garbage for test");
        setField(objectUnderTest, "providers", specs);
        objectUnderTest.execute();
        verify(log, times(1)).info(eq("Provider TestProv loaded."));
    }

    @Test
    public void testProvidersClassDoesntExist() throws Exception
    {
        ProviderSpec[] specs = new ProviderSpec[1];
        specs[0] = new ProviderSpec();
        specs[0].setClassName("xpertss.crypto.kms.provider.NonProvider");
        setField(objectUnderTest, "providers", specs);
        MojoExecutionException e = assertThrows(MojoExecutionException.class, () -> {
            objectUnderTest.execute();
        });
        assertEquals("Provider xpertss.crypto.kms.provider.NonProvider with appropriate constructor not found", e.getMessage());
        verify(log, never()).info(eq("Provider KMS loaded."));
    }

    @Test
    public void testProvidersNotProvider() throws Exception
    {
        ProviderSpec[] specs = new ProviderSpec[1];
        specs[0] = new ProviderSpec();
        specs[0].setClassName("java.lang.StringBuilder");
        setField(objectUnderTest, "providers", specs);
        MojoExecutionException e = assertThrows(MojoExecutionException.class, () -> {
            objectUnderTest.execute();
        });
        assertEquals("Provider java.lang.StringBuilder is not an implementation of java.security.Provider", e.getMessage());
        verify(log, never()).info(eq("Provider KMS loaded."));
    }


    @Test
    public void testFindProxy()
    {
        List<Proxy> proxies = createTestProxies();
        when(settings.getProxies()).thenReturn(proxies);
        java.net.Proxy proxy = objectUnderTest.findProxyFor(URI.create("https://tsa.digicert.com/"));
        assertEquals(java.net.Proxy.class, proxy.getClass());
        InetSocketAddress address = new InetSocketAddress("https.mydomain.com", 8000);
        assertEquals(address, proxy.address());
    }

    @Test
    public void testFindProxyNotLocalhost()
    {
        List<Proxy> proxies = createTestProxies();
        when(settings.getProxies()).thenReturn(proxies);
        java.net.Proxy proxy = objectUnderTest.findProxyFor(URI.create("http://localhost/"));
        assertEquals(java.net.Proxy.class, proxy.getClass());
        InetSocketAddress address = new InetSocketAddress("http.mydomain.com", 8000);
        assertEquals(address, proxy.address());
    }

    @Test
    public void testFindProxyHttp()
    {
        List<Proxy> proxies = createTestProxies();
        when(settings.getProxies()).thenReturn(proxies);
        java.net.Proxy proxy = objectUnderTest.findProxyFor(URI.create("http://timestamp.digicert.com/"));
        assertEquals(java.net.Proxy.class, proxy.getClass());
        InetSocketAddress address = new InetSocketAddress("remote.mydomain.com", 8000);
        assertEquals(address, proxy.address());
    }

    @Test
    public void testFindProxyWithUserCreds()
    {
        Proxy proxy = createProxy("proxy.mydomain.com", 8080, true);
        proxy.setUsername("joeblow");
        proxy.setPassword("yearight");
        when(settings.getProxies()).thenReturn(Collections.singletonList(proxy));
        java.net.Proxy p = objectUnderTest.findProxyFor(URI.create("http://timestamp.digicert.com/"));
        assertEquals(AuthenticatedProxy.class, p.getClass());
    }




    @Test
    public void testSingleArchive() throws Exception
    {
        setField(objectUnderTest, "archive", new File("test.jar"));
        objectUnderTest.execute();
        assertEquals(1, objectUnderTest.seen.size());
        assertTrue(objectUnderTest.seen.contains(Paths.get("test.jar")));
    }

    @Test
    public void testNonExistentMainArtifact() throws Exception
    {
        Artifact artifact = mock(Artifact.class);
        when(artifact.getFile()).thenReturn(new File("test.txt"));

        setTrue(objectUnderTest, "processMainArtifact");
        when(project.getArtifact()).thenReturn(artifact);
        objectUnderTest.execute();
        assertTrue(objectUnderTest.seen.isEmpty());
    }

    @Test
    public void testMainArtifact() throws Exception
    {
        Artifact artifact = mock(Artifact.class);
        when(artifact.getFile()).thenReturn(target.toFile());

        setTrue(objectUnderTest, "processMainArtifact");
        when(project.getArtifact()).thenReturn(artifact);
        objectUnderTest.execute();
        assertEquals(1, objectUnderTest.seen.size());
        assertTrue(objectUnderTest.seen.contains(target));
    }

    @Test
    public void testAttachedArtifact_excludedByClassifier() throws Exception
    {
        Artifact artifact = mock(Artifact.class);
        //when(artifact.getFile()).thenReturn(target.toFile());
        when(artifact.getClassifier()).thenReturn("test");

        setTrue(objectUnderTest, "processAttachedArtifacts");
        setField(objectUnderTest, "excludeClassifiers", new String[] { "test" });
        when(project.getAttachedArtifacts()).thenReturn(Collections.singletonList(artifact));
        objectUnderTest.execute();
        assertTrue(objectUnderTest.seen.isEmpty());
    }

    @Test
    public void testAttachedArtifact_notIncludedByClassifier() throws Exception
    {
        Artifact artifact = mock(Artifact.class);
        //when(artifact.getFile()).thenReturn(target.toFile());
        when(artifact.getClassifier()).thenReturn("test");

        setTrue(objectUnderTest, "processAttachedArtifacts");
        setField(objectUnderTest, "includeClassifiers", new String[] { "provided" });
        when(project.getAttachedArtifacts()).thenReturn(Collections.singletonList(artifact));
        objectUnderTest.execute();
        assertTrue(objectUnderTest.seen.isEmpty());
    }

    @Test
    public void testAttachedArtifact_notExcluded() throws Exception
    {
        Artifact artifact = mock(Artifact.class);
        when(artifact.getFile()).thenReturn(target.toFile());
        when(artifact.getClassifier()).thenReturn("test");

        setTrue(objectUnderTest, "processAttachedArtifacts");
        setField(objectUnderTest, "excludeClassifiers", new String[] { "runtime" });
        when(project.getAttachedArtifacts()).thenReturn(Collections.singletonList(artifact));
        objectUnderTest.execute();
        assertEquals(1, objectUnderTest.seen.size());
        assertTrue(objectUnderTest.seen.contains(target));
    }


    @Test
    public void testAttachedArtifact_explicitlyIncluded() throws Exception
    {
        Artifact artifact = mock(Artifact.class);
        when(artifact.getFile()).thenReturn(target.toFile());
        when(artifact.getClassifier()).thenReturn("test");

        setTrue(objectUnderTest, "processAttachedArtifacts");
        setField(objectUnderTest, "includeClassifiers", new String[] { "test" });
        when(project.getAttachedArtifacts()).thenReturn(Collections.singletonList(artifact));
        objectUnderTest.execute();
        assertEquals(1, objectUnderTest.seen.size());
        assertTrue(objectUnderTest.seen.contains(target));
    }







    public static class TestJarSignerMojo extends AbstractJarsignerMojo {

        Set<Path> seen = new LinkedHashSet<>();

        protected TestJarSignerMojo(SecDispatcher securityDispatcher)
        {
            super(securityDispatcher);
        }

        @Override
        protected void processArchive(Path archive) throws MojoExecutionException {
            seen.add(archive);
        }
    }




    private void setTrue(Object instance, String fieldName)
        throws Exception
    {
        Field field = getField(instance.getClass(), fieldName);
        if(!field.getType().equals(boolean.class))
            throw new IllegalArgumentException("expected " + fieldName + " to be boolean type");
        field.setAccessible(true);
        field.setBoolean(instance, true);

    }

    private void setField(Object instance, String fieldName, Object value)
        throws Exception
    {
        Field field = getField(instance.getClass(), fieldName);
        if(!field.getType().isAssignableFrom(value.getClass()))
            throw new IllegalArgumentException("invalid type for field " + fieldName);
        field.setAccessible(true);
        field.set(instance, value);
    }

    private Field getField(Class<?> clazz, String fieldName)
    {
        while(clazz != Object.class) {
            Field[] fields = clazz.getDeclaredFields();
            Optional<Field> field = Arrays.stream(fields).
                            filter(field1 -> fieldName.equals(field1.getName())).findFirst();
            if(field.isPresent()) return field.get();
            clazz = clazz.getSuperclass();
        }
        return null;
    }



    private static List<Proxy> createTestProxies()
    {
        List<Proxy> proxies = new ArrayList<>();
        proxies.add(createProxy("disabled.mydomain.com", 8000, false));
        proxies.add(createProxy("remote.mydomain.com", 8000, true, "localhost"));
        proxies.add(createProxy("http.mydomain.com", 8000, true));
        proxies.add(createProxy("https", "https.mydomain.com", 8000, true));
        return proxies;
    }

    private static Proxy createProxy(String host, int port, boolean active)
    {
        Proxy proxy = new Proxy();
        proxy.setActive(active);
        proxy.setHost(host);
        proxy.setPort(port);
        return proxy;
    }

    private static Proxy createProxy(String protocol, String host, int port, boolean active)
    {
        Proxy proxy = createProxy(host, port, active);
        proxy.setProtocol(protocol);
        return proxy;
    }

    private static Proxy createProxy(String host, int port, boolean active, String nonProxyHosts)
    {
        Proxy proxy = createProxy(host, port, active);
        proxy.setNonProxyHosts(nonProxyHosts);
        return proxy;
    }

}