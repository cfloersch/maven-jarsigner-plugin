package org.xpertss.jarsigner.tsa;

import org.xpertss.crypto.asn1.AsnUtil;
import org.xpertss.crypto.pkcs.tsp.TimeStampRequest;
import org.xpertss.crypto.pkcs.tsp.TimeStampResponse;

import java.io.BufferedInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URI;

/**
 * A timestamper that communicates with a Timestamping Authority (TSA)
 * over HTTP.
 *
 * It supports the Time-Stamp Protocol defined in:
 * <a href="http://www.ietf.org/rfc/rfc3161.txt">RFC 3161</a>.
 *
 * TODO Update to RFC 5816
 * https://datatracker.ietf.org/doc/html/rfc5816
 *
 * TODO Might also be worth while to figure out the proxyHost/Port/etc
 */
public class HttpTimestamper implements Timestamper {

    private static final int CONNECT_TIMEOUT = 15000; // 15 seconds

    // The MIME type for a timestamp query
    private static final String TS_QUERY_MIME_TYPE =
            "application/timestamp-query";

    // The MIME type for a timestamp reply
    private static final String TS_REPLY_MIME_TYPE =
            "application/timestamp-reply";

    /*
     * HTTP URI identifying the location of the TSA
     */
    private URI tsaURI = null;

    /**
     * Creates a timestamper that connects to the specified TSA.
     *
     * @param tsa The location of the TSA. It must be an HTTP or HTTPS URI.
     * @throws IllegalArgumentException if tsaURI is not an HTTP or HTTPS URI
     */
    public HttpTimestamper(URI tsa)
    {
        if (!tsa.getScheme().equalsIgnoreCase("http") &&
                !tsa.getScheme().equalsIgnoreCase("https")) {
            throw new IllegalArgumentException(
                    "TSA must be an HTTP or HTTPS URI");
        }
        this.tsaURI = tsa;
    }

    /**
     * Connects to the TSA and requests a timestamp.
     *
     * @param tsQuery The timestamp query.
     * @return The result of the timestamp query.
     * @throws IOException The exception is thrown if a problem occurs while
     *         communicating with the TSA.
     */
    public TimeStampResponse generateTimestamp(TimeStampRequest tsQuery)
        throws IOException
    {

        // TODO Need to build a ProxyManager or something that allows us to determine
        // what proxy to use for given URL given nonProxyHosts
        // may also need user creds via Authenticator (no way to directly associate)
        // generally speaking I don't think TSA require authentication so may be overkill
        // We could of course just set the Authorization header to basic with the creds (assumes basic auth)
        Authenticator authenticator = null;
        Proxy proxy = Proxy.NO_PROXY;


        HttpURLConnection connection = (HttpURLConnection) tsaURI.toURL().openConnection(proxy);

        connection.setDoOutput(true);
        connection.setUseCaches(false); // ignore cache
        connection.setRequestProperty("Content-Type", TS_QUERY_MIME_TYPE);
        connection.setRequestMethod("POST");
        // Avoids the "hang" when a proxy is required but none has been set.
        connection.setConnectTimeout(CONNECT_TIMEOUT);
        connection.connect(); // No HTTP authentication is performed

        // Send the request
        DataOutputStream output = null;
        try {
            output = new DataOutputStream(connection.getOutputStream());
            byte[] request = AsnUtil.encode(tsQuery);
            output.write(request, 0, request.length);
            output.flush();
        } finally {
            if (output != null) {
                output.close();
            }
        }

        // Receive the reply
        BufferedInputStream input = null;
        byte[] replyBuffer = null;
        try {
            input = new BufferedInputStream(connection.getInputStream());
            verifyMimeType(connection.getContentType());

            int clen = connection.getContentLength();
            //replyBuffer = IOUtils.readAllBytes(input);    // TODO
            if (clen != -1 && replyBuffer.length != clen)
                throw new EOFException("Expected:" + clen +
                        ", read:" + replyBuffer.length);

        } finally {
            if (input != null) {
                input.close();
            }
        }
        return AsnUtil.decode(new TimeStampResponse(), replyBuffer);
    }

    /*
     * Checks that the MIME content type is a timestamp reply.
     *
     * @param contentType The MIME content type to be checked.
     * @throws IOException The exception is thrown if a mismatch occurs.
     */
    private static void verifyMimeType(String contentType) throws IOException {
        if (! TS_REPLY_MIME_TYPE.equalsIgnoreCase(contentType)) {
            throw new IOException("MIME Content-Type is not " +
                    TS_REPLY_MIME_TYPE);
        }
    }

}
