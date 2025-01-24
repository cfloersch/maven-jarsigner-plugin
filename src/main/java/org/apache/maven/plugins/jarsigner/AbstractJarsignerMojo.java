package org.apache.maven.plugins.jarsigner;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.text.MessageFormat;
import java.util.*;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.apache.maven.settings.Settings;
import org.xpertss.jarsigner.JarSignerUtil;
import org.apache.maven.shared.utils.ReaderFactory;
import org.apache.maven.shared.utils.StringUtils;
import org.apache.maven.shared.utils.cli.javatool.JavaToolException;
import org.apache.maven.shared.utils.io.FileUtils;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcher;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcherException;

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
     * See <a href="https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    @Parameter(property = "jarsigner.strict", defaultValue = "false")
    private boolean strict;


    /**
     * POJO containing Security Provider configuration
     */
    @Parameter
    private ProviderSpec provider;


    // TODO Move next two to Sign

    /**
     * See <a href="https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    @Parameter(property = "jarsigner.alias")
    private String alias;

    /**
     * POJO containing keystore configuration
     */
    @Parameter
    private KeyStoreSpec keystore;




    // TODO -
    // private File trustStore;





    /**
     * The base directory to scan for JAR files using Ant-like inclusion/exclusion patterns.
     */
    @Parameter(property = "jarsigner.archiveDirectory")
    private File archiveDirectory;

    /**
     * The Ant-like inclusion patterns used to select JAR files to process. The patterns must be
     * relative to the directory given by the parameter {@link #archiveDirectory}. By default, the
     * pattern <code>&#42;&#42;/&#42;.?ar</code> is used.
     */
    @Parameter
    private String[] includes = {"**/*.?ar"};

    /**
     * The Ant-like exclusion patterns used to exclude JAR files from processing. The patterns must be
     * relative to the directory given by the parameter {@link #archiveDirectory}.
     */
    @Parameter
    private String[] excludes = {};









    /**
     * Controls processing of the main artifact produced by the project.
     */
    @Parameter(property = "jarsigner.processMainArtifact", defaultValue = "true")
    private boolean processMainArtifact;

    /**
     * Controls processing of project attachments. If enabled, attached artifacts that are no JAR/ZIP
     * files will be automatically excluded from processing.
     */
    @Parameter(property = "jarsigner.processAttachedArtifacts", defaultValue = "true")
    private boolean processAttachedArtifacts;


    /**
     * A set of artifact classifiers describing the project attachments that should be processed. This
     * parameter is only relevant if {@link #processAttachedArtifacts} is <code>true</code>. If empty,
     * all attachments are included.
     */
    @Parameter
    private String[] includeClassifiers;

    /**
     * A set of artifact classifiers describing the project attachments that should not be processed. This parameter is
     * only relevant if {@link #processAttachedArtifacts} is <code>true</code>. If empty, no attachments are excluded.
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




    /**
     * TODO Do I need this?
     */
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
    }


    /**
     * Validate the user supplied configuration/parameters.
     *
     * @throws MojoExecutionException if the user supplied configuration make further execution impossible
     */
    protected void configure()
       throws MojoExecutionException
    {
        System.out.println("Keystore: " + keystore);
        System.out.println("Provider: " + provider);
        // Default implementation does nothing
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
            return Arrays.asList(this.archive.toPath());
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
    protected final void processArchive(final Path archive) throws MojoExecutionException {
        if (archive == null) {
            throw new NullPointerException("archive");
        }

        preProcessArchive(archive);

        getLog().info(getMessage("processing", archive));

        // TODO was used to setup JarSigner

        // Preserves 'file.encoding' the plugin is executed with.
        final List<String> additionalArguments = new ArrayList<>();

        boolean fileEncodingSeen = false;

        if (!fileEncodingSeen) {
            additionalArguments.add("-J-Dfile.encoding=" + ReaderFactory.FILE_ENCODING);
        }



        // Adds proxy information. TODO Operate on these more directly in TSA Impl
        if (this.settings != null
                && this.settings.getActiveProxy() != null
                && StringUtils.isNotEmpty(this.settings.getActiveProxy().getHost())) {
            additionalArguments.add(
                    "-J-Dhttp.proxyHost=" + this.settings.getActiveProxy().getHost());
            additionalArguments.add(
                    "-J-Dhttps.proxyHost=" + this.settings.getActiveProxy().getHost());
            additionalArguments.add(
                    "-J-Dftp.proxyHost=" + this.settings.getActiveProxy().getHost());

            if (this.settings.getActiveProxy().getPort() > 0) {
                additionalArguments.add(
                        "-J-Dhttp.proxyPort=" + this.settings.getActiveProxy().getPort());
                additionalArguments.add(
                        "-J-Dhttps.proxyPort=" + this.settings.getActiveProxy().getPort());
                additionalArguments.add(
                        "-J-Dftp.proxyPort=" + this.settings.getActiveProxy().getPort());
            }

            if (StringUtils.isNotEmpty(this.settings.getActiveProxy().getNonProxyHosts())) {
                additionalArguments.add("-J-Dhttp.nonProxyHosts=\""
                        + this.settings.getActiveProxy().getNonProxyHosts() + "\"");

                additionalArguments.add("-J-Dftp.nonProxyHosts=\""
                        + this.settings.getActiveProxy().getNonProxyHosts() + "\"");
            }
        }



        // TODO Special handling for passwords through the Maven Security Dispatcher
        // What does this really do and do I really need it?
        //request.setStorepass(decrypt(storepass));

        /*
        try {
            // TODO Actually sign jar
            //executeJarSigner(jarSigner, request);
        } catch (JavaToolException e) {
            throw new MojoExecutionException(getMessage("commandLineException", e.getMessage()), e);
        }

         */
    }

    /**
     * Executes jarsigner (execute signing or verification for a jar file).
     *
     * @throws JavaToolException if jarsigner could not be invoked
     * @throws MojoExecutionException if the invocation of jarsigner succeeded, but returned a non-zero exit code
     *
     * TODO This can go away replaced by an abstract version of processArchive
     */
    protected abstract void executeJarSigner()
            throws JavaToolException, MojoExecutionException;



    
    // TODO Where does it get encrypted??
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
        return artifact != null && artifact.getFile() != null && JarSignerUtil.isZipFile(artifact.getFile());
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
        if (artifact == null) {
            throw new NullPointerException("artifact");
        }

        if (isZipFile(artifact)) {
            return Optional.of(artifact.getFile().toPath());
        }

        getLog().debug(getMessage("unsupported", artifact));
        return Optional.empty();
    }

}
