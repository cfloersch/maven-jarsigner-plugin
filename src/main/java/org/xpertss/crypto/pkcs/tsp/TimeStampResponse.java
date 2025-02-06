package org.xpertss.crypto.pkcs.tsp;

import org.xpertss.crypto.asn1.ASN1Sequence;
import org.xpertss.crypto.pkcs.pkcs7.ContentInfo;
import org.xpertss.crypto.pkcs.pkcs7.SignedData;

/**
 * This class provides the response corresponding to a timestamp response, as defined in
 * <a href="http://www.ietf.org/rfc/rfc3161.txt">RFC 3161</a>.
 * <p/>
 * The TimeStampResp ASN.1 type has the following definition:
 * <pre>
 *
 *     TimeStampResp ::= SEQUENCE {
 *         status            PKIStatusInfo,
 *         timeStampToken    TimeStampToken OPTIONAL ]
 *
 *     PKIStatusInfo ::= SEQUENCE {
 *         status        PKIStatus,
 *         statusString  PKIFreeText OPTIONAL,
 *         failInfo      PKIFailureInfo OPTIONAL }
 *
 *     PKIStatus ::= INTEGER {
 *         granted                (0),
 *           -- when the PKIStatus contains the value zero a TimeStampToken, as
 *           -- requested, is present.
 *         grantedWithMods        (1),
 *           -- when the PKIStatus contains the value one a TimeStampToken,
 *           -- with modifications, is present.
 *         rejection              (2),
 *         waiting                (3),
 *         revocationWarning      (4),
 *           -- this message contains a warning that a revocation is
 *           -- imminent
 *         revocationNotification (5)
 *           -- notification that a revocation has occurred }
 *
 *     PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
 *           -- text encoded as UTF-8 String (note:  each UTF8String SHOULD
 *           -- include an RFC 1766 language tag to indicate the language
 *           -- of the contained text)
 *
 *     PKIFailureInfo ::= BIT STRING {
 *         badAlg              (0),
 *           -- unrecognized or unsupported Algorithm Identifier
 *         badRequest          (2),
 *           -- transaction not permitted or supported
 *         badDataFormat       (5),
 *           -- the data submitted has the wrong format
 *         timeNotAvailable    (14),
 *           -- the TSA's time source is not available
 *         unacceptedPolicy    (15),
 *           -- the requested TSA policy is not supported by the TSA
 *         unacceptedExtension (16),
 *           -- the requested extension is not supported by the TSA
 *         addInfoNotAvailable (17)
 *           -- the additional information requested could not be understood
 *           -- or is not available
 *         systemFailure       (25)
 *           -- the request cannot be handled due to system failure }
 *
 *     TimeStampToken ::= ContentInfo
 *         -- contentType is id-signedData
 *         -- content is SignedData
 *           -- eContentType within SignedData is id-ct-TSTInfo
 *           -- eContent within SignedData is TSTInfo
 *
 * </pre>
 */
public class TimeStampResponse extends ASN1Sequence {


    /**
     * The requested timestamp was granted.
     */
    public static final int GRANTED = 0;

    /**
     * The requested timestamp was granted with some modifications.
     */
    public static final int GRANTED_WITH_MODS = 1;

    /**
     * The requested timestamp was not granted.
     */
    public static final int REJECTION = 2;

    /**
     * The requested timestamp has not yet been processed.
     */
    public static final int WAITING = 3;

    /**
     * A warning that a certificate revocation is imminent.
     */
    public static final int REVOCATION_WARNING = 4;

    /**
     * Notification that a certificate revocation has occurred.
     */
    public static final int REVOCATION_NOTIFICATION = 5;





    // Failure codes (from RFC 3161)

    /**
     * Unrecognized or unsupported algorithm identifier.
     */
    public static final int BAD_ALG = 0;

    /**
     * The requested transaction is not permitted or supported.
     */
    public static final int BAD_REQUEST = 2;

    /**
     * The data submitted has the wrong format.
     */
    public static final int BAD_DATA_FORMAT = 5;

    /**
     * The TSA's time source is not available.
     */
    public static final int TIME_NOT_AVAILABLE = 14;

    /**
     * The requested TSA policy is not supported by the TSA.
     */
    public static final int UNACCEPTED_POLICY = 15;

    /**
     * The requested extension is not supported by the TSA.
     */
    public static final int UNACCEPTED_EXTENSION = 16;

    /**
     * The additional information requested could not be understood or is not
     * available.
     */
    public static final int ADD_INFO_NOT_AVAILABLE = 17;

    /**
     * The request cannot be handled due to system failure.
     */
    public static final int SYSTEM_FAILURE = 25;




    private PKIStatusInfo status;

    private ContentInfo token;

    /**
     * Create an instance of TimeStampResponse ready to decode a response from a stream or
     * byte source.
     */
    public TimeStampResponse()
    {
        super(2);

        status = new PKIStatusInfo();
        add(status);

        token = new ContentInfo();
        token.setOptional(true);
        add(token);
    }

    /**
     * Create an instance of TimeStampResponse ready to encode a response to a stream or
     * byte source.
     * <p/>
     * Simple success (or success with modifications) response.
     *
     * @param statusCode The status code to respond with
     * @param token The token to respond with
     */
    public TimeStampResponse(int statusCode, ContentInfo token)
    {
        super(2);

        status = new PKIStatusInfo(statusCode);
        add(status);

        this.token = (ContentInfo) token.copy();
        add(this.token);

        // TODO Verify there is no reason to send messages on success??
    }

    /**
     * Create an instance of TimeStampResponse ready to encode a response to a stream or
     * byte source.
     * <p/>
     * Simple failure response with messages. No token is returned in the failure cases.
     *
     * @param statusCode The status code to respond with
     * @param messages The messages to respond with in the PKIFreeText
     */
    public TimeStampResponse(int statusCode, String ... messages)
    {
        super(2);
        status = new PKIStatusInfo(statusCode, messages);
        add(status);
        // TODO may need variant that includes ContentInfo token
    }

    /**
     * Create an instance of TimeStampResponse ready to encode a response to a stream or
     * byte source.
     * <p/>
     * Simple failure response with failure codes. No token is returned in the failure cases.
     *
     * @param statusCode The status code to respond with
     * @param failures The failure codes to respond with as a bit string
     */
    public TimeStampResponse(int statusCode, boolean[] failures)
    {
        super(2);
        status = new PKIStatusInfo(statusCode, failures);
        add(status);
    }



    /**
     * Create an instance of TimeStampResponse ready to encode a response to a stream or
     * byte source.
     * <p/>
     * Simple failure response with failure codes. No token is returned in the failure cases.
     *
     * @param statusCode The status code to respond with
     * @param failures The failure codes to respond with as a bit string
     * @param messages The messages to respond with in the PKIFreeText
     */
    public TimeStampResponse(int statusCode, boolean[] failures, String ... messages)
    {
        super(2);
        status = new PKIStatusInfo(statusCode, failures, messages);
        add(status);
    }





    /**
     * Retrieve the status code returned by the TSA.
     */
    public int getStatusCode()
    {
        return status.getStatusCode();
    }

    /**
     * Retrieve the status messages returned by the TSA.
     *
     * @return If null then no status messages were received.
     */
    public String[] getStatusMessages()
    {
        return status.getStatusMessages();
    }

    /**
     * Retrieve the failure info returned by the TSA.
     *
     * @return the failure info, or null if no failure code was received.
     */
    public boolean[] getFailureInfo()
    {
        return status.getFailureInfo();
    }

    /**
     * Utility method to check the failure info bit string for individual failure reasons.
     *
     * @param failureCode One of the defined failure codes as a bit position.
     */
    public boolean isFailure(int failureCode)
    {
        boolean[] failures = status.getFailureInfo();
        return failures != null && failures.length > failureCode && failures[failureCode];
    }


    public String getStatusCodeAsText()
    {
        switch (status.getStatusCode())  {
            case GRANTED:
                return "the timestamp request was granted.";

            case GRANTED_WITH_MODS:
                return "the timestamp request was granted with some modifications.";

            case REJECTION:
                return "the timestamp request was rejected.";

            case WAITING:
                return "the timestamp request has not yet been processed.";

            case REVOCATION_WARNING:
                return "warning: a certificate revocation is imminent.";

            case REVOCATION_NOTIFICATION:
                return "notification: a certificate revocation has occurred.";

            default:
                return ("unknown status code " + status + ".");
        }
    }




    public ContentInfo getToken()
    {
        return (token.isOptional()) ? null : token;
    }

    public TSTokenInfo getTimestampTokenInfo()
    {
        SignedData signedData = (SignedData) token.getContent();
        if(signedData == null) return null;

        // TODO Even though contentType is a TSTokenInfo, it is actually a Data instance (aka OctetString)
        //  so I will need to grab the bytes and parse it. How to handle the exceptions?
        // I can create a subclass of OctetString (kind of like Data) which decodes those bytes into TSTokenInfo on decode()
        // With the getContent() returning the TSTokenInfo like it is supposed to


        // TODO Check contentType or just use ClassCastException??
        //  1.2.840.113549.1.9.16.1.4
        return (TSTokenInfo) signedData.getContent();
    }


}
