# jarsigner-maven-plugin

This is a drop in replacement for the standard apache maven jar signing plugin that utilizes a built
in jar signing implementation rather than forking out to the command line tool. This allows maven to
manage the dependency tree. 

Most users will probably be fine using the standard Java JCE or PKCS11 implementations. However, for
those that would like to do builds on any machine utilizing services like AWS KMS, this implementation
is for you.

At it's heart this library allows you to include third party JCE Providers using Maven's standard 
dependency management model. It provides a more robust mechanism for dynamically installing those 
providers and specifying those providers along with the keystore, digest, and signature algorithms.

Otherwise, the functionality is very similar to that of the built in jarsigner. This can perform
both models.

Example usage
```xml
      <plugin>
        <groupId>org.xpertss.maven.plugins</groupId>
        <artifactId>jarsigner-maven-plugin</artifactId>
        <version>1.0.0-SNAPSHOT</version>
        <dependencies>
          <dependency>
            <groupId>org.xpertss</groupId>
            <artifactId>aws-kms</artifactId>
            <version>1.0.0-SNAPSHOT</version>
          </dependency>
        </dependencies>
        <configuration>
          <providers>
            <providerClass>xpertss.crypto.kms.provider.KmsProvider</providerClass>
          </providers>
          <keystore>
            <path>NONE</path>
            <provider>KMS</provider>
          </keystore>
          <certchain>kms-rsa4096-certchain.pem</certchain>
          <alias>test-01</alias>
          <sigfile>TESTING</sigfile>
          <signature>
            <algorithm>SHA386withRSA</algorithm>
            <provider>KMS</provider>
          </signature>
          <processMainArtifact>false</processMainArtifact>
          <archiveDirectory>target/classes/jars</archiveDirectory>
        </configuration>
        <executions>
          <execution>
            <id>sign-jars</id>
            <goals>
              <goal>sign</goal>
            </goals>
          </execution>
        </executions>
      </plugin>
```
             
Dynamic Provider Installation
-----------------------------

In most cases the only JCE Providers you will need are the ones that come pre-installed within the JVM.
For those that need something else, you now have a solution. This implementation allows you to include
as a standard maven dependency any provider you wish and a mechanism to configure it's installation on
any build machine.

```xml
      <plugin>
        <groupId>org.xpertss.maven.plugins</groupId>
        <artifactId>jarsigner-maven-plugin</artifactId>
        <version>1.0.0-SNAPSHOT</version>
        <dependencies>
          <dependency>
            <groupId>org.xpertss</groupId>
            <artifactId>aws-kms</artifactId>
            <version>1.0.0-SNAPSHOT</version>
          </dependency>
        </dependencies>
        <configuration>
          <providers>
            <providerClass>xpertss.crypto.kms.provider.KmsProvider</providerClass>
          </providers>
        </configuration>
      </plugin>
```

In the above example, we simply include our aws-kms provider as a standard plugin dependency. And we
use the `providers` configuration to instruct the jarsigner to install the KmsProvdier within the
VM's Security context.


Identity Stores
---------------

The Java Jarsigner classifies a KeyStore as the basis for the signer identity. Generally, this
store will contain both the private key used for signing as well as the certificate chain issued
by a certificate authority.

Many modern FIPS compliant hardware systems do not have the ability to store and maintain the
certificate chain associated with the private key. That is certainly true of the AWS Key Mgmt
Service  (KMS). This implementation allows you to define both parts of the identity independently:

```xml
      <keystore>
        <path>NONE</path>
        <provider>aws-kms</provider>
      </keystore>
      <certchain>kms-rsa4096-certchain.pem</certchain>
```

In the above example the keystore is defined with a specific provider name and NO underlying file.
The keystore provides access to the underlying private key in a network centric and hardware manner.
The associated certificate is specified separately from a file located on the disk. In this case the
credentials necessary to access the keystore are provided in a more AWS centric way and do not need
to be included in the maven configuration.


Trust Store
-----------

Another capability this platform provides is a means to define the trust store. The trust store
is more commonly referred to as the Trusted Certificates store or the Trusted CA Root Certificate
database. By default this comes pre-installed with your JVM. This implementation allows you to
specify an alternative trust store to use as a config parameter.

```xml
   <truststore>../trusted-certs.p12</truststore>
```

The trust store is simply a standard Java KeyStore file located somewhere in your build or on the
build system. it contains trusted certificates including self-signed certificates your organization
may manage.

Most users will not need this, but for those that do. Now you have a solution.


Compatibility
-------------

This implementation supports all of the default capabilities of the Apache maven jar signer, although
some of the arguments may be slightly different. For example to define a timestamp authority you would
do something like the following:

```xml
    <plugin>
       <groupId>org.xpertss.maven.plugins</groupId>
       <artifactId>jarsigner-maven-plugin</artifactId>
       <version>1.0.0-SNAPSHOT</version>
       <configuration>
          <keystore>
             <path>${keystore.file}</path>
             <storepass>${keystore.storepass}</storepass>
             <storetype>JKS</storetype>
             <provider>SUN</provider>
          </keystore>
          <alias>test-01</alias>
          <keypass>${alias.keypass}</keypass>
          <sigfile>TESTING</sigfile>
          <processMainArtifact>true</processMainArtifact>
          <tsa>
             <uri>http://timestamp.digicert.com</uri>
             <policyId>2.16.840.1.114412.7.1</policyId>
             <digestAlg>SHA-386</digestAlg>
          </tsa>
          <clean>true</clean>
          <strict>true</strict>
       </configuration>
       <executions>
          <execution>
             <id>sign-jars</id>
             <goals>
                <goal>sign</goal>
             </goals>
          </execution>
       </executions>
    </plugin>
```

In the above example we use a standard keystore model along with a timestamp authority. What is different is the
`clean` property which implies that any existing signature should be removed as we sign the archive with a new
signature. Also notice the `strict` parameter. This parameter will force the jarsigner to fail if any of the 
keys used in the process are invalid, unusable for code signing, untrusted, etc. The default implementation will
output a log line warning of the issue but will not fail. That is the behavior here if `strict` is set to false
which is the default value.

Note that `processMainArtifact` is the exact same parameter as used in the Maven jarsigner. All of the parameters
associated with the archives, and or directories to sign are the same. Other parameters that are the same as 
those in the Apache variant include `keypass`, `sigfile`, and `alias`.


Designated Algorithms
---------------------

The JRE jarsigner allows you to specify signature and digest algorithms to use. However, there is no real way to
associate those with a particular provider. When using third party providers like the AWS-KMS provider you must
use it's variant of the signature algorithm with it's keys as the actual signing process is operating remotely
and the key is really just a pointer to a network resource.

```xml
   <configuration>
      <keystore>
         <path>NONE</path>
         <storepass>${keystore.storepass}</storepass>
         <provider>KMS</provider>
      </keystore>
      <alias>test-01</alias>
      <signature>
         <algorithm>SHA386withRSA</algorithm>
         <provider>KMS</provider>
      </signature>
      <digest>
         <algorithm>SHA512</algorithm>
         <provider>SUN</provider>
      </digest>
   </configuration>
```

In the above example we use both the KMS keystore and signature algorithms but we use the SUN built in
digest algorithm.
