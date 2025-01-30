/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 1/19/2025
 */
package org.xpertss.jarsigner;


import org.xpertss.jarsigner.pkcs.PKCS9Attribute;
import org.xpertss.jarsigner.pkcs.PKCS9Attributes;

import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Objects;

public final class TsaSigner {

    private final URI uri;

    private String policyId;
    private String digest;


    private TsaSigner(Builder builder)
    {
        this.uri = builder.uri;
        this.policyId = builder.policyId;
        this.digest = builder.digestAlg;
    }


    public URI getUri()
    {
        return uri;
    }

    public String getDigestAlgorithm()
    {
        return (digest == null) ? "SHA-256" : digest;
    }

    public String getPolicyId()
    {
        return policyId;
    }


    public PKCS9Attributes stamp(byte[] signature)
    {
        // Create HttpTimestamper
        byte[] tsToken = null;

        // TODO get timestamp..
        // https://github.com/JetBrains/jdk8u_jdk/blob/master/src/share/classes/sun/security/pkcs/PKCS7.java#L872
        // HttpTimestamper tsa = new HttpTimestamper(tsaURI);
        //https://github.com/JetBrains/jdk8u_jdk/blob/master/src/share/classes/sun/security/timestamp/HttpTimestamper.java#L50

        return new PKCS9Attributes(new PKCS9Attribute(PKCS9Attribute.SIGNATURE_TIMESTAMP_TOKEN_STR, tsToken));
    }

    @Override
    public String toString()
    {
        StringBuilder builder = new StringBuilder();
        builder.append(String.format("uri=%s", uri));
        if(policyId != null) {
            builder.append(String.format(", policyId=%s", policyId));
        }
        if(digest != null) {
            builder.append(String.format(", digest=%s", digest));
        }
        return builder.insert(0, "[").append("]").toString();
    }



    public static class Builder {

        private URI uri;
        private String digestAlg;
        private String policyId;

        private Builder(URI uri)
        {
            this(uri, null);
        }

        // Do I need this from parsing the cert
        private Builder(URI uri, String policyId)
        {
            this.uri = Objects.requireNonNull(uri, "uri");
            this.policyId = policyId;
        }



        public Builder digestAlgorithm(String digestAlg)
            throws NoSuchAlgorithmException
        {
            if(digestAlg != null) MessageDigest.getInstance(digestAlg);
            this.digestAlg = digestAlg;
            return this;
        }

        public Builder policyId(String policyId)
        {
            this.policyId = policyId;
            return this;
        }




        public TsaSigner build()
        {
            return new TsaSigner(this);
        }




        
        /*
        https://www.freetsa.org/index_en.php

        Owner: ST=Bayern, C=DE, L=Wuerzburg, EMAILADDRESS=busilezas@gmail.com, CN=www.freetsa.org, OID.2.5.4.13=This certificate digitally signs documents and time stamp requests made using the freetsa.org online services, OU=TSA, O=Free TSA
        Issuer: C=DE, ST=Bayern, L=Wuerzburg, EMAILADDRESS=busilezas@gmail.com, CN=www.freetsa.org, OU=Root CA, O=Free TSA
        Serial number: c1e986160da8e982
        Valid from: Sat Mar 12 20:57:39 EST 2016 until: Tue Mar 10 21:57:39 EDT 2026
        Certificate fingerprints:
                 MD5:  CB:2C:A4:D3:6F:8A:45:C2:F6:B7:76:1A:01:F5:FC:44
                 SHA1: 91:6D:A3:D8:60:EC:CA:82:E3:4B:C5:9D:17:93:E7:E9:68:87:5F:14
                 SHA256: 46:94:BE:23:C3:A5:30:04:44:4B:17:05:BF:E5:A7:F5:0A:6D:2A:16:38:19:4F:23:C0:F3:89:B6:8B:D7:8A:75
                 Signature algorithm name: SHA512withRSA
                 Version: 3

        Extensions:

        #1: ObjectId: 2.5.29.14 Criticality=false
        SubjectKeyIdentifier [
          KeyIdentifier: [6E:76:0B:7B:4E:4F:9C:E1:60:CA:6D:2C:E9:27:A2:A2:94:B3:77:37]
        ]

        #2: ObjectId: 2.5.29.35 Criticality=false
        AuthorityKeyIdentifier [
          KeyIdentifier: [FA:55:0D:8C:34:66:51:43:4C:F7:E7:B3:A7:6C:95:AF:7A:E6:A4:97]
        ]

        #3: ObjectId: 2.5.29.31 Criticality=false
        CRLDistributionPoints [
          DistributionPoint:  [URIName: http://www.freetsa.org/crl/root_ca.crl]
        ]

        #4: ObjectId: 2.5.29.32 Criticality=false
        CertificatePolicies [
          CertificatePolicyId: [0.0]
          PolicyQualifierInfo: [Certification Practice Statement]
          PolicyQualifierInfo: [Certification Practice Statement]
          PolicyQualifierInfo: [User Notice]
        ]

        #5: ObjectId: 2.5.29.37 Criticality=true
        ExtendedKeyUsages [
          timeStamping
        ]

        #6: ObjectId: 2.5.29.15 Criticality=false
        KeyUsage [
          DigitalSignature
          Non_repudiation
        ]

        #7: ObjectId: 1.3.6.1.5.5.7.1.1 Criticality=false
        AuthorityInfoAccess [
          Certificate Authority Issuer
            URIName: http://www.freetsa.org/tsa.crt
          On-line Certificate Status Protocol
            URIName: http://www.freetsa.org:2560
        ]

        #8: ObjectId: 2.5.29.19 Criticality=false
        BasicConstraints:[
          CA:false
          PathLen: undefined
        ]
         */
        public static Builder of(Certificate cert)
            throws CertificateException
        {
            throw new CertificateException("Subject Information Access extension not found");
            // TODO Throw exception if certificate is not for
            //  keyUsage (non-repudiation || digitalSignature)
            //  extKeyUsage (timestamping)


            // TODO Extract uri and policyId if present
            // https://code.googlesource.com/edge/openjdk/+/refs/heads/master/jdk/src/share/classes/sun/security/tools/jarsigner/TimestampedSigner.java#155
            //return null;
        }

        public static Builder of(URI uri)
        {
            return new Builder(uri);
        }

    }

}
