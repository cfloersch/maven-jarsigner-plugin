# jarsigner-maven-plugin
This is a drop in replacement for the standard apache maven jar signing plugin that utilizes a built
in jar signing implementation rather than forking out to the command line tool. This allows maven to
manage the dependency tree. 

This supports the use of dependent Providers that are not already installed on the system. For example
implementations that integrate AWS KMS Hardware signing systems.

In addition this implementation supports a more specific and capable argument model allowing individual
providers to be named for each algorithm defined helping to minimize conflicts between naming.

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
            <storepass>${keystore.storepass}</storepass>
          </keystore>
          <alias>test-01</alias>
          <sigfile>TESTING</sigfile>
          <certchain>kms-rsa4096-certchain.pem</certchain>
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
          <execution>
            <id>verify-jars</id>
            <goals>
              <goal>verify</goal>
            </goals>
          </execution>
        </executions>
      </plugin>
```


