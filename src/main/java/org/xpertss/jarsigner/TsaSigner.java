/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 1/19/2025
 */
package org.xpertss.jarsigner;


import org.xpertss.crypto.pkcs.PKCS9Attribute;
import org.xpertss.crypto.pkcs.PKCS9Attributes;

import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

// Sun Timestamper Impl
// https://github.com/JetBrains/jdk8u_jdk/tree/master/src/share/classes/sun/security/timestamp
// https://www.ietf.org/rfc/rfc5035.txt
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





        public static Builder of(URI uri)
        {
            return new Builder(uri);
        }


    }

}
