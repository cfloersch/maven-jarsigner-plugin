/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 1/19/2025
 */
package org.xpertss.jarsigner;


import java.net.URI;
import java.security.cert.Certificate;
import java.util.Objects;

public class TSASigner {

    private final URI uri;

    private TSASigner(Builder builder)
    {
        this.uri = builder.uri;
    }


    public void sign()
    {
        // TODO get timestamp..
    }


    public static class Builder {

        private URI uri;
        private String digestAlg;
        private String policyId;

        private Builder(URI uri)
        {
            this.uri = Objects.requireNonNull(uri, "uri");
        }

        // Do I need this from parsing the cert
        private Builder(URI uri, String digestAlg)
        {
            this.uri = Objects.requireNonNull(uri, "uri");
            this.digestAlg = digestAlg;
        }



        public Builder digestAlgorithm(String digestAlg)
        {
            this.digestAlg = digestAlg;
            return this;
        }

        public Builder policyId(String policyId)
        {
            this.policyId = policyId;
            return this;
        }

        public TSASigner build()
        {
            return null;    // TODO
        }


        public static Builder of(Certificate cert)
        {
            // TODO Extract uri
            return null;
        }

        public static Builder of(URI uri)
        {
            return new Builder(uri);
        }

    }

}
