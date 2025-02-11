package org.xpertss.jarsigner.plugins;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;
import java.text.MessageFormat;
import java.util.*;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.apache.maven.settings.Proxy;
import org.apache.maven.settings.Settings;
import org.apache.maven.shared.utils.StringUtils;
import org.apache.maven.shared.utils.io.FileUtils;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcher;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcherException;
import org.xpertss.jarsigner.jar.ArchiveUtils;
import org.xpertss.jarsigner.tsa.AuthenticatedProxy;

/**
 * Maven Jarsigner Plugin base class.
 */
public abstract class AbstractJarsignerMojo extends AbstractMojo {


    /**
     * Set to {@code true} to disable the plugin.
     */
    @Parameter(property = "jarsigner.skip", defaultValue = "false")
    private boolean skip;


    /**
     * POJO containing Security Provider configuration
     */
    @Parameter
    private ProviderSpec[] providers;





    /**
     * The base directory to scan for JAR files using Ant-like inclusion/exclusion patterns.
     */
    @Parameter(property = "jarsigner.archiveDirectory")
    private File archiveDirectory;

    /**
     * The Ant-like inclusion patterns used to select JAR files to process. The patterns
     * must be relative to the directory given by the parameter {@link #archiveDirectory}.
     * By default, the pattern <code>&#42;&#42;/&#42;.?ar</code> is used.
     */
    @Parameter
    private String[] includes = {"**/*.?ar"};

    /**
     * The Ant-like exclusion patterns used to exclude JAR files from processing. The
     * patterns must be relative to the directory given by the parameter {@link
     * #archiveDirectory}.
     */
    @Parameter
    private String[] excludes = {};









    /**
     * Controls processing of the main artifact produced by the project.
     */
    @Parameter(property = "jarsigner.processMainArtifact", defaultValue = "true")
    private boolean processMainArtifact;

    /**
     * Controls processing of project attachments. If enabled, attached artifacts that
     * are no JAR/ZIP files will be automatically excluded from processing.
     */
    @Parameter(property = "jarsigner.processAttachedArtifacts", defaultValue = "true")
    private boolean processAttachedArtifacts;


    /**
     * A set of artifact classifiers describing the project attachments that should be
     * processed. This parameter is only relevant if {@link #processAttachedArtifacts} is
     * <code>true</code>. If empty, all attachments are included.
     */
    @Parameter
    private String[] includeClassifiers;

    /**
     * A set of artifact classifiers describing the project attachments that should not be
     * processed. This parameter is only relevant if {@link #processAttachedArtifacts} is
     * <code>true</code>. If empty, no attachments are excluded.
     */
    @Parameter
    private String[] excludeClassifiers;



    /**
     * Archive to process. If set, neither the project artifact nor any attachments or archive
     * sets are processed.
     *
     * TODO Do I want this?
     */
    @Parameter(property = "jarsigner.archive")
    private File archive;



    /**
     * The Maven project.
     */
    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;

    /**
     * The Maven settings.
     */
    @Parameter(defaultValue = "${settings}", readonly = true, required = true)
    private Settings settings;

    /**
     * Location of the working directory.
     */
    @Parameter(defaultValue = "${project.basedir}")
    private File workingDirectory;

    /**
     * The current build session instance. This is used for
     * toolchain manager API calls.
     */
    @Parameter(defaultValue = "${session}", readonly = true, required = true)
    private MavenSession session;









    private final SecDispatcher securityDispatcher;


    protected AbstractJarsignerMojo(SecDispatcher securityDispatcher)
    {
        this.securityDispatcher = securityDispatcher;
    }









    @Override
    public final void execute()
       throws MojoExecutionException
    {
        if (this.skip) {
            getLog().info(getMessage("disabled"));
            return;
        }

        prepareProviders();
        configure();

        List<Path> archives = findJarfiles();
        processArchives(archives);

        getLog().info(getMessage("processed", archives.size()));
    }




    private void prepareProviders()
       throws MojoExecutionException
    {
        if (providers != null) {
            for (ProviderSpec provider: providers) {
                try {
                    Class<?> clazz = Class.forName(provider.getClassName());
                    Provider prov = null;
                    if (provider.getArgument() != null) {
                        Constructor<?> c =
                           clazz.getConstructor(String.class);
                        prov = (Provider) c.newInstance(provider.getArgument());;
                    } else {
                        prov = (Provider) clazz.newInstance();;
                    }
                    Security.addProvider(prov);
                    getLog().info(getMessage("provider.loaded", prov.getName()));
                } catch (ClassCastException cce) {
                    throw new MojoExecutionException(getMessage("provider.class.not.a.provider", provider.getClassName()));
                } catch (ReflectiveOperationException  e) {
                    throw new MojoExecutionException(getMessage("provider.class.not.found", provider.getClassName()), e.getCause());
                }
            }
        }
    }


    /**
     * Validate the user supplied configuration/parameters.
     *
     * @throws MojoExecutionException if the user supplied configuration make further execution impossible
     */
    protected void configure()
       throws MojoExecutionException
    {
        // Default implementation does nothing
    }


    protected java.net.Proxy findProxyFor(URI uri)
    {
        Proxy proxy = findActiveProxy(uri.getScheme(), uri.getHost());
        if(proxy != null) {
            InetSocketAddress address = new InetSocketAddress(proxy.getHost(), proxy.getPort());
            if(StringUtils.isNotEmpty(proxy.getUsername())) {
                return new AuthenticatedProxy(java.net.Proxy.Type.HTTP, address, proxy.getUsername(), proxy.getPassword());
            } else {
                return new java.net.Proxy(java.net.Proxy.Type.HTTP, address);
            }
        }
        return java.net.Proxy.NO_PROXY;
    }

    private Proxy findActiveProxy(String protocol, String host)
    {
        for(Proxy proxy : settings.getProxies()) {
            if(proxy.isActive() && matchesProtocol(protocol, proxy.getProtocol())) {
                String nonProxied = proxy.getNonProxyHosts();
                if(nonProxied != null && !nonProxied.isEmpty()) {
                    String[] patterns = nonProxied.split("[|]");
                    if(matchesNone(patterns, host)) return proxy;
                } else {
                    return proxy;
                }
            }
        }
        return null;
    }

    private boolean matchesProtocol(String protocol, String proxyProtocol)
    {
        return (StringUtils.isEmpty(proxyProtocol)
                    || proxyProtocol.equalsIgnoreCase(protocol));
    }

    private boolean matchesNone(String[] patterns, String host)
    {
        InetAddress hostInet = NetUtils.getInetAddress(host);
        if(hostInet == null) return false;
        for(String pattern : patterns) {
            if(NetUtils.matches(pattern, hostInet)) return false;
        }
        return true;
    }


    /**
     * Finds all jar files, by looking at the Maven project and user configuration.
     *
     * @return a List of File objects
     * @throws MojoExecutionException if it was not possible to build a list of jar files
     */
    private List<Path> findJarfiles()
        throws MojoExecutionException
    {
        if (this.archive != null) {
            // Only process this, but nothing more
            return Collections.singletonList(this.archive.toPath());
        }

        List<Path> archives = new ArrayList<>();
        if (processMainArtifact) {
            getFileFromArtifact(this.project.getArtifact()).ifPresent(archives::add);
        }

        if (processAttachedArtifacts) {
            Collection<String> includes = new HashSet<>();
            if (includeClassifiers != null) {
                includes.addAll(Arrays.asList(includeClassifiers));
            }

            Collection<String> excludes = new HashSet<>();
            if (excludeClassifiers != null) {
                excludes.addAll(Arrays.asList(excludeClassifiers));
            }

            for (Artifact artifact : this.project.getAttachedArtifacts()) {
                if (!includes.isEmpty() && !includes.contains(artifact.getClassifier())) {
                    continue;
                }

                if (excludes.contains(artifact.getClassifier())) {
                    continue;
                }

                getFileFromArtifact(artifact).ifPresent(archives::add);
            }
        } else {
            getLog().debug(getMessage("ignoringAttachments"));
        }

        if (archiveDirectory != null) {

            String includeList = (includes != null) ? String.join(",", includes) : null;
            String excludeList = (excludes != null) ? String.join(",", excludes) : null;

            try {
                FileUtils.getFiles(archiveDirectory, includeList, excludeList)
                                .forEach(file -> archives.add(file.toPath()));
            } catch (IOException e) {
                throw new MojoExecutionException("Failed to scan archive directory for JARs: " + e.getMessage(), e);
            }
        }

        return archives;
    }






    /**
     * Pre-processes a given archive.
     *
     * @param archive The archive to process, must not be <code>null</code>.
     * @throws MojoExecutionException if pre-processing failed
     */
    protected void preProcessArchive(final Path archive)
       throws MojoExecutionException
    {
        // Default implementation does nothing
    }



    /**
     * Process (sign/verify) a list of archives.
     *
     * @param archives list of jar files to process
     * @throws MojoExecutionException if an error occurs during the processing of archives
     */
    protected void processArchives(List<Path> archives) throws MojoExecutionException {
        for (Path file : archives) {
            processArchive(file);
        }
    }

    /**
     * Processes a given archive.
     *
     * @param archive The archive to process.
     * @throws NullPointerException if {@code archive} is {@code null}
     * @throws MojoExecutionException if processing {@code archive} fails
     */
    protected abstract void processArchive(final Path archive) throws MojoExecutionException;




    
    protected String decrypt(String encoded) throws MojoExecutionException {
        try {
            return securityDispatcher.decrypt(encoded);
        } catch (SecDispatcherException e) {
            getLog().error("error using security dispatcher: " + e.getMessage(), e);
            throw new MojoExecutionException("error using security dispatcher: " + e.getMessage(), e);
        }
    }




    
    /**
     * Gets a message for a given key from the resource bundle backing the implementation.
     *
     * @param key the key of the message to return
     * @param args arguments to format the message with
     * @return the message with key {@code key} from the resource bundle backing the implementation
     * @throws NullPointerException if {@code key} is {@code null}
     * @throws java.util.MissingResourceException
     *             if there is no message available matching {@code key} or accessing
     *             the resource bundle fails
     */
    String getMessage(final String key, final Object... args) {
        if (key == null) throw new NullPointerException("key");
        return new MessageFormat(ResourceBundle.getBundle("jarsigner").getString(key)).format(args);
    }



    /**
     * Checks whether the specified artifact is a ZIP file.
     *
     * @param artifact The artifact to check, may be <code>null</code>.
     * @return <code>true</code> if the artifact looks like a ZIP file, <code>false</code> otherwise.
     */
    private static boolean isZipFile(final Artifact artifact)
    {
        return artifact != null && artifact.getFile() != null && ArchiveUtils.isZipFile(artifact.getFile());
    }

    /**
     * Examines an Artifact and extract the File object pointing to the Artifact jar file.
     *
     * @param artifact the artifact to examine
     * @return An Optional containing the File, or Optional.empty() if the File is not a jar file.
     * @throws NullPointerException if {@code artifact} is {@code null}
     */
    private Optional<Path> getFileFromArtifact(final Artifact artifact)
    {
        if (artifact == null) throw new NullPointerException("artifact");

        if (isZipFile(artifact)) {
            return Optional.of(artifact.getFile().toPath());
        }

        getLog().debug(getMessage("unsupported", artifact));
        return Optional.empty();
    }



}
