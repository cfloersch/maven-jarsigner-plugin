/*
 * Copyright 2025 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 1/19/2025
 */
package org.xpertss.jarsigner;




import org.apache.maven.shared.utils.StringUtils;
import org.xpertss.crypto.asn1.AsnUtil;
import org.xpertss.crypto.pkcs.pkcs7.ContentInfo;
import org.xpertss.crypto.pkcs.pkcs7.SignedData;
import org.xpertss.crypto.pkcs.pkcs7.SignerInfo;
import org.xpertss.crypto.pkcs.tsp.TSTokenInfo;
import org.xpertss.crypto.pkcs.tsp.TimeStampRequest;
import org.xpertss.crypto.pkcs.tsp.TimeStampResponse;
import org.xpertss.jarsigner.tsa.HttpTimestamper;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Proxy;
import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

/**
 * An implementation of time stamp protocol that interacts with a TSA and produces a
 * timestamp token that can be included in our signature.
 */
// Sun Timestamper Impl
// https://github.com/JetBrains/jdk8u_jdk/tree/master/src/share/classes/sun/security/timestamp
// https://www.ietf.org/rfc/rfc5035.txt
public final class TsaSigner {

    private final SecureRandom random = new SecureRandom();

    private final URI uri;

    private String policyId;
    private String digest;

    private TrustStore trustStore;
    private boolean strict;

    private Proxy proxy;


    private TsaSigner(Builder builder)
    {
        this.uri = builder.uri;
        this.policyId = builder.policyId;
        this.digest = builder.digestAlg;
        this.trustStore = builder.trustStore;
        this.strict = builder.strict;
        this.proxy = builder.proxy;
    }


    /**
     * Returns the URI of the Time Stamp Authority this will use to generate timestamp tokens.
     */
    public URI getUri()
    {
        return uri;
    }

    /**
     * Returns the message digest algorithm this implementation will use to produce the hash
     * the TSA will sign and return. It must be one the TSA supports.
     */
    public String getDigestAlgorithm()
    {
        return (digest == null) ? "SHA-256" : digest;
    }

    /**
     * The TSA specific policyId we are requesting the TSA to apply when generating the timestamp.
     */
    public String getPolicyId()
    {
        return policyId;
    }


    /**
     * Given a signature, crate a time stamp token, and return it as a BER encoded ContentInfo
     * structure. The ContentInfo defined in PKCS7 will include an embedded SignedData object
     * which itself will include the TSTInfo content entry.
     * <p/>
     * The resulting encoded object can be used as the attribute value for PKCS9 attributes
     * which are attached to the signature as unauthenticated attributes.
     *
     * @param signature The signature to timestamp
     * @return A BER encoded ContentInfo structure.
     */
    public byte[] stamp(byte[] signature)
        throws NoSuchAlgorithmException, IOException,
                CertificateException, CertPathValidatorException
    {
        BigInteger NONCE = new BigInteger(64, random);

        digest = (StringUtils.isEmpty(digest)) ? "SHA-256" : digest;

        MessageDigest md = MessageDigest.getInstance(digest);
        TimeStampRequest request = new TimeStampRequest(md.getAlgorithm(), md.digest(signature));
        if(StringUtils.isNotEmpty(policyId)) request.setPolicy(policyId);
        request.setNonce(NONCE);
        request.setRequestCertificate(true);

        HttpTimestamper timestamper = new HttpTimestamper(uri, proxy);
        TimeStampResponse response = timestamper.generateTimestamp(request);
        if(response.getStatusCode() > 1) {
            throw new IOException("Error generating timestamp: " + response.getStatusCodeAsText());
        }
        TSTokenInfo tstInfo = response.getTimestampTokenInfo();

        if (StringUtils.isNotEmpty(policyId) && !policyId.equals(tstInfo.getPolicyID())) {
            throw new IOException("TSAPolicyID changed in timestamp token");
        }

        // TODO A bunch of validation of NONCE, Hashes, Digest Alg, policyId, etc
        /*
        try {
            if (!tstInfo.getHashAlgorithm().equals(AlgorithmId.get(digest))) {
                throw new IOException("Digest algorithm not " + digest + " in "
                   + "timestamp token");
            }
        } catch (NoSuchAlgorithmException nase) {
            throw new IllegalArgumentException();   // should have been caught before
        }
        */

        if (!MessageDigest.isEqual(tstInfo.getHashedMessage(),
                                    request.getHashedMessage())) {
            throw new IOException("Digest octets changed in timestamp token");
        }

        BigInteger replyNonce = tstInfo.getNonce();
        if (replyNonce == null) {
            throw new IOException("Nonce missing in timestamp token");
        } else if(!replyNonce.equals(NONCE)) {
            throw new IOException("Nonce changed in timestamp token");
        }

        ContentInfo content = response.getToken();
        SignedData singedData = (SignedData) content.getContent();
        for(SignerInfo signer : singedData.getSignerInfos()) {
            List<X509Certificate> chain = singedData.getCertificates(signer);
            if (chain.isEmpty()) throw new CertificateException("Certificate not included in timestamp token");
            if (strict) trustStore.validate(chain, KeyUsage.Timestamping);
        }
        return AsnUtil.encode(content);
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

        private TrustStore trustStore;
        private boolean strict;

        private Proxy proxy;


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


        public Builder proxiedBy(Proxy proxy)
        {
            this.proxy = proxy;
            return this;
        }

        public Builder strict(boolean value)
        {
            this.strict = value;
            return this;
        }

        public Builder trustStore(TrustStore store)
        {
            this.trustStore = store;
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
