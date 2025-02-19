/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.maven.jarsigner;

import org.apache.maven.shared.utils.cli.javatool.AbstractJavaToolRequest;

import java.io.File;

/**
 * Specifies the commons parameters used to control a jar signer invocation.
 *
 * @author Tony Chemit
 * @since 1.0
 */
public abstract class AbstractJarSignerRequest extends AbstractJavaToolRequest implements JarSignerRequest {
    /**
     * See <a href="http://docs.oracle.com/javase/6/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    private boolean verbose;

    /**
     * See <a href="http://docs.oracle.com/javase/6/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    private File keystore;

    /**
     * See <a href="http://docs.oracle.com/javase/6/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    private String storetype;

    /**
     * See <a href="http://docs.oracle.com/javase/6/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    private String storepass;

    /**
     * See <a href="http://docs.oracle.com/javase/6/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    private String alias;

    /**
     * See <a href="http://docs.oracle.com/javase/6/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    private String providerName;

    /**
     * See <a href="http://docs.oracle.com/javase/6/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    private String providerClass;

    /**
     * See <a href="http://docs.oracle.com/javase/6/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    private String providerArg;

    /**
     * The maximum memory available to the JAR signer, e.g. <code>256M</code>. See <a
     * href="http://docs.oracle.com/javase/6/docs/technotes/tools/windows/java.html#Xms">-Xmx</a> for more details.
     */
    private String maxMemory;

    /**
     * List of additional arguments to append to the jarsigner command line.
     */
    private String[] arguments;

    /**
     * Location of the working directory.
     */
    private File workingDirectory;

    /**
     * Archive to treat.
     */
    private File archive;

    /**
     * See <a href="http://java.sun.com/javase/6/docs/technotes/tools/windows/jarsigner.html#Options">options</a>.
     */
    protected boolean protectedAuthenticationPath;


    private String classpath;


    /**
     * {@inheritDoc}
     */
    public boolean isVerbose() {
        return verbose;
    }

    /**
     * {@inheritDoc}
     */
    public File getKeystore() {
        return keystore;
    }

    /**
     * {@inheritDoc}
     */
    public String getStoretype() {
        return storetype;
    }

    /**
     * {@inheritDoc}
     */
    public String getStorepass() {
        return storepass;
    }

    /**
     * {@inheritDoc}
     */
    public String getAlias() {
        return alias;
    }

    /**
     * {@inheritDoc}
     */
    public String getProviderName() {
        return providerName;
    }

    /**
     * {@inheritDoc}
     */
    public String getProviderClass() {
        return providerClass;
    }

    /**
     * {@inheritDoc}
     */
    public String getProviderArg() {
        return providerArg;
    }

    /**
     * {@inheritDoc}
     */
    public String getMaxMemory() {
        return maxMemory;
    }

    /**
     * {@inheritDoc}
     */
    public String[] getArguments() {
        return arguments;
    }

    /**
     * {@inheritDoc}
     */
    public File getWorkingDirectory() {
        return workingDirectory;
    }

    /**
     * {@inheritDoc}
     */
    public File getArchive() {
        return archive;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isProtectedAuthenticationPath() {
        return protectedAuthenticationPath;
    }


    public String getClasspath() { return classpath; }


    /**
     * {@inheritDoc}
     */
    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    /**
     * {@inheritDoc}
     */
    public void setKeystore(File keystore) {
        this.keystore = keystore;
    }

    /**
     * {@inheritDoc}
     */
    public void setStoretype(String storetype) {
        this.storetype = storetype;
    }

    /**
     * {@inheritDoc}
     */
    public void setStorepass(String storepass) {
        this.storepass = storepass;
    }

    /**
     * {@inheritDoc}
     */
    public void setProviderName(String providerName) {
        this.providerName = providerName;
    }

    /**
     * {@inheritDoc}
     */
    public void setProviderClass(String providerClass) {
        this.providerClass = providerClass;
    }

    /**
     * {@inheritDoc}
     */
    public void setProviderArg(String providerArg) {
        this.providerArg = providerArg;
    }

    /**
     * {@inheritDoc}
     */
    public void setAlias(String alias) {
        this.alias = alias;
    }

    /**
     * {@inheritDoc}
     */
    public void setMaxMemory(String maxMemory) {
        this.maxMemory = maxMemory;
    }

    /**
     * {@inheritDoc}
     */
    public void setArguments(String... arguments) {
        this.arguments = arguments;
    }

    /**
     * {@inheritDoc}
     */
    public void setWorkingDirectory(File workingDirectory) {
        this.workingDirectory = workingDirectory;
    }

    /**
     * {@inheritDoc}
     */
    public void setArchive(File archive) {
        this.archive = archive;
    }

    /**
     * {@inheritDoc}
     */
    public void setProtectedAuthenticationPath(boolean protect) {
        this.protectedAuthenticationPath = protect;
    }


    public void setClasspath(String classpath) { this.classpath = classpath; }


}
