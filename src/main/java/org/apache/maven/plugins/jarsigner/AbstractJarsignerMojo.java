package org.apache.maven.plugins.jarsigner;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.MessageFormat;
import java.util.*;
import java.util.stream.Collectors;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.apache.maven.settings.Settings;
import org.apache.maven.jarsigner.JarSigner;
import org.apache.maven.jarsigner.JarSignerRequest;
import org.apache.maven.jarsigner.JarSignerUtil;
import org.apache.maven.shared.utils.ReaderFactory;
import org.apache.maven.shared.utils.StringUtils;
import org.apache.maven.shared.utils.cli.Commandline;
import org.apache.maven.shared.utils.cli.javatool.JavaToolException;
import org.apache.maven.shared.utils.io.FileUtils;
import org.apache.maven.toolchain.Toolchain;
import org.apache.maven.toolchain.ToolchainManager;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcher;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcherException;

/**
 * Maven Jarsigner Plugin base class.
 *
 * @author <a href="cs@schulte.it">Christian Schulte</a>
 */
public abstract class AbstractJarsignerMojo extends AbstractMojo {

    /**
     * See <a href="https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    @Parameter(property = "jarsigner.verbose", defaultValue = "false")
    private boolean verbose;

    /**
     * See <a href="https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    @Parameter(property = "jarsigner.keystore")
    private File keystore;

    /**
     * See <a href="https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    @Parameter(property = "jarsigner.storetype")
    private String storetype;

    /**
     * See <a href="https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    @Parameter(property = "jarsigner.storepass")
    private String storepass;

    /**
     * See <a href="https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    @Parameter(property = "jarsigner.providerName")
    private String providerName;

    /**
     * See <a href="https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    @Parameter(property = "jarsigner.providerClass")
    private String providerClass;

    /**
     * See <a href="https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    @Parameter(property = "jarsigner.providerArg")
    private String providerArg;

    /**
     * See <a href="https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    @Parameter(property = "jarsigner.alias")
    private String alias;

    /**
     * The maximum memory available to the JAR signer, e.g. <code>256M</code>. See <a
     * href="https://docs.oracle.com/javase/7/docs/technotes/tools/windows/java.html#Xms">-Xmx</a>
     * for more details.
     */
    @Parameter(property = "jarsigner.maxMemory")
    private String maxMemory;

    /**
     * Archive to process. If set, neither the project artifact nor any attachments or archive
     * sets are processed.
     */
    @Parameter(property = "jarsigner.archive")
    private File archive;

    /**
     * The base directory to scan for JAR files using Ant-like inclusion/exclusion patterns.
     *
     * @since 1.1
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
     * List of additional arguments to append to the jarsigner command line. Each argument should be
     * specified as a separate element. For example, to specify the name of the signed jar, two
     * elements are needed:
     * <ul>
     *     <li>Alternative using the command line: {@code -Djarsigner.arguments="-signedjar,my-project_signed.jar"}</li>
     *     <li>Alternative using the Maven POM configuration:</li>
     * </ul>
     * <pre>
     * {@code
     * <configuration>
     *   <arguments>
     *     <argument>-signedjar</argument>
     *     <argument>my-project_signed.jar</argument>
     *   </arguments>
     * </configuration>
     * }</pre>
     */
    @Parameter(property = "jarsigner.arguments")
    private String[] arguments;

    /**
     * Set to {@code true} to disable the plugin.
     */
    @Parameter(property = "jarsigner.skip", defaultValue = "false")
    private boolean skip;

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
     * Must be set to true if the password must be given via a protected
     * authentication path such as a dedicated PIN reader.
     */
    @Parameter(property = "jarsigner.protectedAuthenticationPath", defaultValue = "false")
    private boolean protectedAuthenticationPath;

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
     * The Maven project.
     */
    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;

    /**
     * Plugin dependencies that will make up classpath passed to jarsigner
     */
    @Parameter(defaultValue = "${plugin.artifacts}", readonly = true, required = true)
    private List<Artifact> pluginArtifacts;

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




    private final JarSigner jarSigner;

    /**
     * To obtain a toolchain if possible.
     */
    private final ToolchainManager toolchainManager;

    /**
     */
    private final SecDispatcher securityDispatcher;


    protected AbstractJarsignerMojo(
            JarSigner jarSigner, ToolchainManager toolchainManager, SecDispatcher securityDispatcher) {
        this.jarSigner = jarSigner;
        this.toolchainManager = toolchainManager;
        this.securityDispatcher = securityDispatcher;
    }

    @Override
    public final void execute() throws MojoExecutionException {
        if (this.skip) {
            getLog().info(getMessage("disabled"));
            return;
        }

        validateParameters();

        Toolchain toolchain = getToolchain();
        if (toolchain != null) {
            getLog().info("Toolchain in maven-jarsigner-plugin: " + toolchain);
            jarSigner.setToolchain(toolchain);
        }

        List<Path> archives = findJarfiles();
        processArchives(archives);
        getLog().info(getMessage("processed", archives.size()));
    }

    /**
     * Finds all jar files, by looking at the Maven project and user configuration.
     *
     * @return a List of File objects
     * @throws MojoExecutionException if it was not possible to build a list of jar files
     */
    private List<Path> findJarfiles() throws MojoExecutionException {
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
            if (verbose) {
                getLog().info(getMessage("ignoringAttachments"));
            } else {
                getLog().debug(getMessage("ignoringAttachments"));
            }
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
     * Creates the jar signer request to be executed.
     *
     * @param archive the archive file to treat by jarsigner
     * @return the request
     * @throws MojoExecutionException if an exception occurs
     */
    protected abstract JarSignerRequest createRequest(Path archive) throws MojoExecutionException;

    /**
     * Gets a string representation of a {@code Commandline}.
     * <p>
     * This method creates the string representation by calling {@code commandLine.toString()} by default.
     * </p>
     *
     * @param commandLine The {@code Commandline} to get a string representation of.
     * @return The string representation of {@code commandLine}.
     * @throws NullPointerException if {@code commandLine} is {@code null}
     */
    protected String getCommandlineInfo(final Commandline commandLine) {
        if (commandLine == null) {
            throw new NullPointerException("commandLine");
        }

        String commandLineInfo = commandLine.toString();
        commandLineInfo = StringUtils.replace(commandLineInfo, this.storepass, "'*****'");
        return commandLineInfo;
    }

    public String getStoretype() {
        return storetype;
    }

    public String getStorepass() {
        return storepass;
    }

    /**
     * Checks whether the specified artifact is a ZIP file.
     *
     * @param artifact The artifact to check, may be <code>null</code>.
     * @return <code>true</code> if the artifact looks like a ZIP file, <code>false</code> otherwise.
     */
    private static boolean isZipFile(final Artifact artifact) {
        return artifact != null && artifact.getFile() != null && JarSignerUtil.isZipFile(artifact.getFile());
    }

    /**
     * Examines an Artifact and extract the File object pointing to the Artifact jar file.
     *
     * @param artifact the artifact to examine
     * @return An Optional containing the File, or Optional.empty() if the File is not a jar file.
     * @throws NullPointerException if {@code artifact} is {@code null}
     */
    private Optional<Path> getFileFromArtifact(final Artifact artifact) {
        if (artifact == null) {
            throw new NullPointerException("artifact");
        }

        if (isZipFile(artifact)) {
            return Optional.of(artifact.getFile().toPath());
        }

        if (this.verbose) {
            getLog().info(getMessage("unsupported", artifact));
        } else if (getLog().isDebugEnabled()) {
            getLog().debug(getMessage("unsupported", artifact));
        }
        return Optional.empty();
    }

    /**
     * Pre-processes a given archive.
     *
     * @param archive The archive to process, must not be <code>null</code>.
     * @throws MojoExecutionException if pre-processing failed
     */
    protected void preProcessArchive(final Path archive) throws MojoExecutionException {
        // Default implementation does nothing
    }

    /**
     * Validate the user supplied configuration/parameters.
     *
     * @throws MojoExecutionException if the user supplied configuration make further execution impossible
     */
    protected void validateParameters() throws MojoExecutionException {
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

        if (this.verbose) {
            getLog().info(getMessage("processing", archive));
        } else if (getLog().isDebugEnabled()) {
            getLog().debug(getMessage("processing", archive));
        }

        JarSignerRequest request = createRequest(archive);
        request.setVerbose(verbose);
        request.setAlias(alias);
        request.setArchive(archive.toFile());
        request.setKeystore(keystore);
        request.setStoretype(storetype);
        request.setProviderArg(providerArg);
        request.setProviderClass(providerClass);
        request.setProviderName(providerName);
        request.setWorkingDirectory(workingDirectory);
        request.setMaxMemory(maxMemory);
        request.setProtectedAuthenticationPath(protectedAuthenticationPath);


        if(pluginArtifacts != null) {
            String classpath = pluginArtifacts.stream()
                    .filter(entry -> entry.getScope().equalsIgnoreCase("runtime"))
                    .map(entry -> entry.getFile().getAbsolutePath())
                    .collect(Collectors.joining(File.pathSeparator));

            if(!classpath.isEmpty()) {
                String toolsJar = Paths.get(System.getProperty("java.home"),
                                    "../lib/tools.jar")
                                    .normalize().toString();

                classpath = String.join(File.pathSeparator, toolsJar, classpath);
                request.setClasspath(classpath);
            }
        }

        // Preserves 'file.encoding' the plugin is executed with.
        final List<String> additionalArguments = new ArrayList<>();

        boolean fileEncodingSeen = false;

        if (this.arguments != null) {
            for (final String argument : this.arguments) {
                String arg = argument.trim();
                if (arg.startsWith("-J-Dfile.encoding=")) {
                    fileEncodingSeen = true;
                }
                additionalArguments.add(argument);
            }
        }

        if (!fileEncodingSeen) {
            additionalArguments.add("-J-Dfile.encoding=" + ReaderFactory.FILE_ENCODING);
        }



        // Adds proxy information.
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


        request.setArguments(
                !additionalArguments.isEmpty()
                        ? additionalArguments.toArray(new String[additionalArguments.size()])
                        : null);

        // Special handling for passwords through the Maven Security Dispatcher
        request.setStorepass(decrypt(storepass));

        try {
            executeJarSigner(jarSigner, request);
        } catch (JavaToolException e) {
            throw new MojoExecutionException(getMessage("commandLineException", e.getMessage()), e);
        }
    }

    /**
     * Executes jarsigner (execute signing or verification for a jar file).
     *
     * @param jarSigner the JarSigner execution interface
     * @param request the JarSignerRequest with parameters JarSigner should use
     * @throws JavaToolException if jarsigner could not be invoked
     * @throws MojoExecutionException if the invocation of jarsigner succeeded, but returned a non-zero exit code
     */
    protected abstract void executeJarSigner(JarSigner jarSigner, JarSignerRequest request)
            throws JavaToolException, MojoExecutionException;

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
        if (key == null) {
            throw new NullPointerException("key");
        }

        return new MessageFormat(ResourceBundle.getBundle("jarsigner").getString(key)).format(args);
    }

    /**
     * the part with ToolchainManager lookup once we depend on
     * 2.0.9 (have it as prerequisite). Define as regular component field then.
     * hint: check maven-compiler-plugin code
     *
     * @return Toolchain instance
     */
    private Toolchain getToolchain() {
        Toolchain tc = null;
        if (toolchainManager != null) {
            tc = toolchainManager.getToolchainFromBuildContext("jdk", session);
        }

        return tc;
    }
}
