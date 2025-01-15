# maven-jarsigner-plugin
Extension of the Apache Plugin that operates purely in Java without calling out to command line tool.

This helps to ensure that maven can manage the dependencies used in the signing process such as external
JCE Providers.

To include external Providers you will need to do something like the following:

```xml
  <plugin>
    <groupId>org.xpertss.maven.plugins</groupId>
    <artifactId>jarsigner-maven-plugin</artifactId>
    <version>1.0.0</version>
    <dependencies>
      <dependency>
        <groupId>org.xpertss</groupId>
        <artifactId>aws-kms</artifactId>
        <version>1.0.0</version>
      </dependency>
    </dependencies>
    <configuration>
        <alias>AWS-KMS-RSA4096</alias>
        <keystore>NONE</keystore>
        <storepass>GARBAGE</storepass>
        <storetype>KMS</storetype>
        <providerClass>org.xpertss.crypto.provider.KmsProvider</providerClass>
        <certchain>kms-rsa4096-certchain.pem</certchain>
    </configuration>
  </plugin>
```

