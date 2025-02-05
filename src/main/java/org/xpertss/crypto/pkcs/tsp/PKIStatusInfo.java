package org.xpertss.crypto.pkcs.tsp;

import org.xpertss.crypto.asn1.ASN1BitString;
import org.xpertss.crypto.asn1.ASN1Integer;
import org.xpertss.crypto.asn1.ASN1Sequence;

/**
 * This class provides the response corresponding to a timestamp response status, as
 * defined in <a href="http://www.ietf.org/rfc/rfc3161.txt">RFC 3161</a>.
 * <p/>
 * The TimeStampResp ASN.1 type has the following definition:
 * <pre>
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
 * </pre>
 */
public class PKIStatusInfo extends ASN1Sequence {

    private ASN1Integer status;

    private PKIFreeText freeText;

    private ASN1BitString failureInfo;

    public PKIStatusInfo()
    {
        super(3);
        status = new ASN1Integer();
        add(status);

        freeText = new PKIFreeText();
        add(freeText);  // NOTE Can be optional

        failureInfo = new ASN1BitString(true, false);
        add(failureInfo);
    }

    public int getStatusCode()
    {
        // TODO Do we want to check value for enumerated values?
        return status.getBigInteger().intValue();
    }

    public String[] getStatusMessages()
    {
        return freeText.getMessages();
    }

    /**
     * Retrieve the failure info returned by the TSA.
     *
     * @return the failure info, or null if no failure code was received.
     */
    public boolean[] getFailureInfo()
    {
        return new boolean[0]; // TODO
    }

}
