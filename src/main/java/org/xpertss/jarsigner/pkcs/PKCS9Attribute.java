package org.xpertss.jarsigner.pkcs;

import java.util.Hashtable;
import java.util.Locale;

/*
    TODO Rather than implementing this monolith maybe I should impl
    individual classes for each TYPE. The challenge will be in
    decoding. Maybe use generics to help with TYPES.
 */
public class PKCS9Attribute {

    /**
     * Array of attribute OIDs defined in PKCS9, by number.
     */
    static final ObjectIdentifier[] PKCS9_OIDS = new ObjectIdentifier[18];

    private final static Class<?> BYTE_ARRAY_CLASS;

    static {   // static initializer for PKCS9_OIDS
        for (int i = 1; i < PKCS9_OIDS.length - 2; i++) {
            PKCS9_OIDS[i] =
                    ObjectIdentifier.newInternal(new int[]{1,2,840,113549,1,9,i});
        }
        // Initialize SigningCertificate and SignatureTimestampToken
        // separately (because their values are out of sequence)
        PKCS9_OIDS[PKCS9_OIDS.length - 2] =
                ObjectIdentifier.newInternal(new int[]{1,2,840,113549,1,9,16,2,12});
        PKCS9_OIDS[PKCS9_OIDS.length - 1] =
                ObjectIdentifier.newInternal(new int[]{1,2,840,113549,1,9,16,2,14});

        try {
            BYTE_ARRAY_CLASS = Class.forName("[B");
        } catch (ClassNotFoundException e) {
            throw new ExceptionInInitializerError(e.toString());
        }
    }

    // first element [0] not used
    public static final ObjectIdentifier EMAIL_ADDRESS_OID = PKCS9_OIDS[1];
    public static final ObjectIdentifier UNSTRUCTURED_NAME_OID = PKCS9_OIDS[2];
    public static final ObjectIdentifier CONTENT_TYPE_OID = PKCS9_OIDS[3];
    public static final ObjectIdentifier MESSAGE_DIGEST_OID = PKCS9_OIDS[4];
    public static final ObjectIdentifier SIGNING_TIME_OID = PKCS9_OIDS[5];
    public static final ObjectIdentifier COUNTERSIGNATURE_OID = PKCS9_OIDS[6];
    public static final ObjectIdentifier CHALLENGE_PASSWORD_OID = PKCS9_OIDS[7];
    public static final ObjectIdentifier UNSTRUCTURED_ADDRESS_OID = PKCS9_OIDS[8];
    public static final ObjectIdentifier EXTENDED_CERTIFICATE_ATTRIBUTES_OID
            = PKCS9_OIDS[9];
    public static final ObjectIdentifier ISSUER_SERIALNUMBER_OID = PKCS9_OIDS[10];
    // [11], [12] are RSA DSI proprietary
    // [13] ==> signingDescription, S/MIME, not used anymore
    public static final ObjectIdentifier EXTENSION_REQUEST_OID = PKCS9_OIDS[14];
    public static final ObjectIdentifier SMIME_CAPABILITY_OID = PKCS9_OIDS[15];
    public static final ObjectIdentifier SIGNING_CERTIFICATE_OID = PKCS9_OIDS[16];
    public static final ObjectIdentifier SIGNATURE_TIMESTAMP_TOKEN_OID =
            PKCS9_OIDS[17];
    public static final String EMAIL_ADDRESS_STR = "EmailAddress";
    public static final String UNSTRUCTURED_NAME_STR = "UnstructuredName";
    public static final String CONTENT_TYPE_STR = "ContentType";
    public static final String MESSAGE_DIGEST_STR = "MessageDigest";
    public static final String SIGNING_TIME_STR = "SigningTime";
    public static final String COUNTERSIGNATURE_STR = "Countersignature";
    public static final String CHALLENGE_PASSWORD_STR = "ChallengePassword";
    public static final String UNSTRUCTURED_ADDRESS_STR = "UnstructuredAddress";
    public static final String EXTENDED_CERTIFICATE_ATTRIBUTES_STR =
            "ExtendedCertificateAttributes";
    public static final String ISSUER_SERIALNUMBER_STR = "IssuerAndSerialNumber";
    // [11], [12] are RSA DSI proprietary
    private static final String RSA_PROPRIETARY_STR = "RSAProprietary";
    // [13] ==> signingDescription, S/MIME, not used anymore
    private static final String SMIME_SIGNING_DESC_STR = "SMIMESigningDesc";
    public static final String EXTENSION_REQUEST_STR = "ExtensionRequest";
    public static final String SMIME_CAPABILITY_STR = "SMIMECapability";
    public static final String SIGNING_CERTIFICATE_STR = "SigningCertificate";
    public static final String SIGNATURE_TIMESTAMP_TOKEN_STR =
            "SignatureTimestampToken";

    /**
     * Hashtable mapping names and variant names of supported
     * attributes to their OIDs. This table contains all name forms
     * that occur in PKCS9, in lower case.
     */
    private static final Hashtable<String, ObjectIdentifier> NAME_OID_TABLE =
            new Hashtable<String, ObjectIdentifier>(18);

    static { // static initializer for PCKS9_NAMES
        NAME_OID_TABLE.put("emailaddress", PKCS9_OIDS[1]);
        NAME_OID_TABLE.put("unstructuredname", PKCS9_OIDS[2]);
        NAME_OID_TABLE.put("contenttype", PKCS9_OIDS[3]);
        NAME_OID_TABLE.put("messagedigest", PKCS9_OIDS[4]);
        NAME_OID_TABLE.put("signingtime", PKCS9_OIDS[5]);
        NAME_OID_TABLE.put("countersignature", PKCS9_OIDS[6]);
        NAME_OID_TABLE.put("challengepassword", PKCS9_OIDS[7]);
        NAME_OID_TABLE.put("unstructuredaddress", PKCS9_OIDS[8]);
        NAME_OID_TABLE.put("extendedcertificateattributes", PKCS9_OIDS[9]);
        NAME_OID_TABLE.put("issuerandserialnumber", PKCS9_OIDS[10]);
        NAME_OID_TABLE.put("rsaproprietary", PKCS9_OIDS[11]);
        NAME_OID_TABLE.put("rsaproprietary", PKCS9_OIDS[12]);
        NAME_OID_TABLE.put("signingdescription", PKCS9_OIDS[13]);
        NAME_OID_TABLE.put("extensionrequest", PKCS9_OIDS[14]);
        NAME_OID_TABLE.put("smimecapability", PKCS9_OIDS[15]);
        NAME_OID_TABLE.put("signingcertificate", PKCS9_OIDS[16]);
        NAME_OID_TABLE.put("signaturetimestamptoken", PKCS9_OIDS[17]);
    };

    /**
     * Hashtable mapping attribute OIDs defined in PKCS9 to the
     * corresponding attribute value type.
     */
    private static final Hashtable<ObjectIdentifier, String> OID_NAME_TABLE =
            new Hashtable<ObjectIdentifier, String>(16);
    static {
        OID_NAME_TABLE.put(PKCS9_OIDS[1], EMAIL_ADDRESS_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[2], UNSTRUCTURED_NAME_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[3], CONTENT_TYPE_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[4], MESSAGE_DIGEST_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[5], SIGNING_TIME_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[6], COUNTERSIGNATURE_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[7], CHALLENGE_PASSWORD_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[8], UNSTRUCTURED_ADDRESS_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[9], EXTENDED_CERTIFICATE_ATTRIBUTES_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[10], ISSUER_SERIALNUMBER_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[11], RSA_PROPRIETARY_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[12], RSA_PROPRIETARY_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[13], SMIME_SIGNING_DESC_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[14], EXTENSION_REQUEST_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[15], SMIME_CAPABILITY_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[16], SIGNING_CERTIFICATE_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[17], SIGNATURE_TIMESTAMP_TOKEN_STR);
    }

    /**
     * Acceptable ASN.1 tags for DER encodings of values of PKCS9
     * attributes, by index in <code>PKCS9_OIDS</code>.
     * Sets of acceptable tags are represented as arrays.
    private static final Byte[][] PKCS9_VALUE_TAGS = {
            null,
            {new Byte(DerValue.tag_IA5String)},   // EMailAddress
            {new Byte(DerValue.tag_IA5String),   // UnstructuredName
                    new Byte(DerValue.tag_PrintableString)},
            {new Byte(DerValue.tag_ObjectId)},    // ContentType
            {new Byte(DerValue.tag_OctetString)}, // MessageDigest
            {new Byte(DerValue.tag_UtcTime)},     // SigningTime
            {new Byte(DerValue.tag_Sequence)},    // Countersignature
            {new Byte(DerValue.tag_PrintableString),
                    new Byte(DerValue.tag_T61String)},   // ChallengePassword
            {new Byte(DerValue.tag_PrintableString),
                    new Byte(DerValue.tag_T61String)},   // UnstructuredAddress
            {new Byte(DerValue.tag_SetOf)},       // ExtendedCertificateAttributes
            {new Byte(DerValue.tag_Sequence)},    // issuerAndSerialNumber
            null,
            null,
            null,
            {new Byte(DerValue.tag_Sequence)},    // extensionRequest
            {new Byte(DerValue.tag_Sequence)},    // SMIMECapability
            {new Byte(DerValue.tag_Sequence)},    // SigningCertificate
            {new Byte(DerValue.tag_Sequence)}     // SignatureTimestampToken
    };
     */

    private static final Class<?>[] VALUE_CLASSES = new Class<?>[18];

    static {
        try {
            Class<?> str = Class.forName("[Ljava.lang.String;");

            VALUE_CLASSES[0] = null;  // not used
            VALUE_CLASSES[1] = str;   // EMailAddress
            VALUE_CLASSES[2] = str;   // UnstructuredName
            VALUE_CLASSES[3] =        // ContentType
                    Class.forName("sun.security.util.ObjectIdentifier");
            VALUE_CLASSES[4] = BYTE_ARRAY_CLASS; // MessageDigest (byte[])
            VALUE_CLASSES[5] = Class.forName("java.util.Date"); // SigningTime
            VALUE_CLASSES[6] =        // Countersignature
                    Class.forName("[Lsun.security.pkcs.SignerInfo;");
            VALUE_CLASSES[7] =        // ChallengePassword
                    Class.forName("java.lang.String");
            VALUE_CLASSES[8] = str;   // UnstructuredAddress
            VALUE_CLASSES[9] = null;  // ExtendedCertificateAttributes
            VALUE_CLASSES[10] = null;  // IssuerAndSerialNumber
            VALUE_CLASSES[11] = null;  // not used
            VALUE_CLASSES[12] = null;  // not used
            VALUE_CLASSES[13] = null;  // not used
            VALUE_CLASSES[14] =        // ExtensionRequest
                    Class.forName("sun.security.x509.CertificateExtensions");
            VALUE_CLASSES[15] = null;  // not supported yet
            VALUE_CLASSES[16] = null;  // not supported yet
            VALUE_CLASSES[17] = BYTE_ARRAY_CLASS;  // SignatureTimestampToken
        } catch (ClassNotFoundException e) {
            throw new ExceptionInInitializerError(e.toString());
        }
    }

    /**
     * Array indicating which PKCS9 attributes are single-valued,
     * by index in <code>PKCS9_OIDS</code>.
     */
    private static final boolean[] SINGLE_VALUED = {
            false,
            false,   // EMailAddress
            false,   // UnstructuredName
            true,    // ContentType
            true,    // MessageDigest
            true,    // SigningTime
            false,   // Countersignature
            true,    // ChallengePassword
            false,   // UnstructuredAddress
            false,   // ExtendedCertificateAttributes
            true,    // IssuerAndSerialNumber - not supported yet
            false,   // not used
            false,   // not used
            false,   // not used
            true,    // ExtensionRequest
            true,    // SMIMECapability - not supported yet
            true,    // SigningCertificate
            true     // SignatureTimestampToken
    };


    public PKCS9Attribute(ObjectIdentifier oid, Object value)
    {
        // different oid have different value TYPES
    }

    public PKCS9Attribute(String name, Object value)
    {
        this(getOID(name), value);
    }


    /**
     * Return the OID for a given attribute name or null if we don't recognize
     * the name.
     */
    public static ObjectIdentifier getOID(String name)
    {
        return NAME_OID_TABLE.get(name.toLowerCase(Locale.ENGLISH));
    }

    /**
     * Return the attribute name for a given OID or null if we don't recognize
     * the oid.
     */
    public static String getName(ObjectIdentifier oid)
    {
        return OID_NAME_TABLE.get(oid);
    }
}
